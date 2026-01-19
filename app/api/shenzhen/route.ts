/**
 * 深圳TV API路由
 * 支持11个深圳广播电视台频道
 * Edge Runtime
 */

import { NextRequest, NextResponse } from 'next/server';
import { md5 } from '../utils/crypto';
import { getRealHost } from '../utils/url';

export const runtime = 'edge';

const CHANNEL_MAP: { [key: string]: string } = {
  'szws4k': 'R77mK1v',  // 深圳卫视4k
  'szws': 'AxeFRth',    // 深圳卫视
  'szds': 'ZwxzUXr',    // 都市频道
  'szdsj': '4azbkoY',   // 电视剧频道
  'szgg': '2q76Sw2',    // 公共频道
  'szcj': '3vlcoxP',    // 财经频道
  'szyl': '1q4iPng',    // 娱乐生活频道
  'szse': '1SIQj6s',    // 少儿频道
  'szyd': 'wDF6KJ3',    // 移动电视
  'szyh': 'BJ5u5k2',    // 宜和购物频道
  'szgj': 'sztvgjpd',   // 国际频道
};

const CHANNEL_NAMES: { [key: string]: string } = {
  'szws4k': '深圳卫视4K', 'szws': '深圳卫视', 'szds': '都市频道',
  'szdsj': '电视剧频道', 'szgg': '公共频道', 'szcj': '财经频道',
  'szyl': '娱乐生活', 'szse': '少儿频道', 'szyd': '移动电视',
  'szyh': '宜和购物', 'szgj': '国际频道',
};

const KEY = 'ejow6p6p6hmrm9g96beh2knecdq5kyv9bp0zxyg7';
const HOSTS = 'https://sztv-live.sztv.com.cn';

/**
 * 获取pathname
 */
function getPathname(code: string): string {
  // 深圳台pathname生成算法 - 从Perl CGI移植
  
  // 获取今天0点的时间戳(毫秒)
  // 获取CST时区(UTC+8)今天0点的时间戳(毫秒)
  const now = new Date();
  const cstOffset = 8 * 60 * 60 * 1000;
  const cstNow = new Date(now.getTime() + cstOffset);
  cstNow.setUTCHours(0, 0, 0, 0);
  const timestampStr = (cstNow.getTime() - cstOffset).toString();
  
  // 计算r和l
  let r = 0;
  let l = 0;
  let d = -1;
  
  for (let i = 0; i < code.length; i++) {
    const charCode = code.charCodeAt(i);
    r += charCode;
    if (d !== -1) {
      l += (d - charCode);
    }
    d = charCode;
  }
  r += l;
  
  // 转换为36进制
  const toBase36 = (num: number): string => {
    if (num === 0) return '0';
    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    let result = '';
    while (num > 0) {
      result = chars[num % 36] + result;
      num = Math.floor(num / 36);
    }
    return result;
  };
  
  // 大整数转36进制（使用字符串处理）
  const bigIntToBase36 = (numStr: string): string => {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    let result = '';
    
    const bigIntMod = (str: string, divisor: number): number => {
      let remainder = 0;
      for (const digit of str) {
        remainder = (remainder * 10 + parseInt(digit)) % divisor;
      }
      return remainder;
    };
    
    const bigIntDiv = (str: string, divisor: number): string => {
      let result = '';
      let remainder = 0;
      for (const digit of str) {
        remainder = remainder * 10 + parseInt(digit);
        const quotient = Math.floor(remainder / divisor);
        result += quotient;
        remainder = remainder % divisor;
      }
      return result.replace(/^0+/, '') || '0';
    };
    
    let num = numStr;
    while (num !== '0' && num !== '') {
      const remainder = bigIntMod(num, 36);
      result = chars[remainder] + result;
      num = bigIntDiv(num, 36);
    }
    
    return result || '0';
  };
  
  const s = toBase36(r);
  let c = bigIntToBase36(timestampStr);
  
  // 计算u (c字符串的ASCII码之和)
  let u = 0;
  for (const char of c) {
    u += char.charCodeAt(0);
  }
  
  // 旋转c字符串
  c = c.substring(5) + c.substring(0, 5);
  
  const f = Math.abs(u - r);
  c = s.split('').reverse().join('') + c;
  
  const g = c.substring(0, 4);
  const w = c.substring(4);
  const wday = now.getDay();
  const b = wday % 2;
  
  // 构建m数组
  const m: string[] = [];
  for (let a = 0; a < code.length; a++) {
    if (a % 2 === b) {
      m.push(c[a % c.length]);
    } else {
      const hIndex = a - 1;
      if (hIndex >= 0) {
        const h = code[hIndex];
        const v = g.indexOf(h);
        if (v === -1) {
          m.push(h);
        } else {
          m.push(w[v]);
        }
      } else {
        m.push(g[a % g.length]);
      }
    }
  }
  
  const mStr = m.join('');
  const f36 = toBase36(f);
  const result = (f36.split('').reverse().join('') + mStr).substring(0, code.length);
  
  return result;
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id') || 'szdsj';

  if (id === 'list') {
    let m3u8Content = '#EXTM3U\n';
    
    // 获取真实域名
    const host = getRealHost(request);
    const protocol = request.url.startsWith('https') ? 'https' : 'http';
    const baseUrl = `${protocol}://${host}/api/shenzhen`;
    
    for (const [cid, _] of Object.entries(CHANNEL_MAP)) {
      m3u8Content += `#EXTINF:-1,${CHANNEL_NAMES[cid]}\n${baseUrl}?id=${cid}\n`;
    }
    return new NextResponse(m3u8Content, {
      headers: { 'Content-Type': 'application/vnd.apple.mpegurl' },
    });
  }

  const code = CHANNEL_MAP[id];
  if (!code) {
    return new NextResponse('Channel not found', { status: 404 });
  }

  const dectime = (Math.floor(Date.now() / 1000) + 7200).toString(16);
  const rate = '500';
  const pathname = getPathname(code);
  const path = `/${code}/${rate}/${pathname}.m3u8`;
  const sign = md5(KEY + path + dectime);
  const liveURL = `${HOSTS}${path}?sign=${sign}&t=${dectime}`;

  return NextResponse.redirect(liveURL, 302);
}
