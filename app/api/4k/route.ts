/**
 * 4K频道API路由
 * 支持9个4K超高清频道
 * Edge Runtime
 */

import { NextRequest, NextResponse } from 'next/server';
import { getRealHost } from '../utils/url';

export const runtime = 'edge';

// AES-256-ECB加密key
const AES_KEY = '01234567890123450123456789012345';
const API_URL1 = 'https://api.chinaaudiovisual.cn/web/user/getVisitor';
const API_URL2 = 'https://api.chinaaudiovisual.cn/column/getColumnList';

// 频道映射表
const CHANNEL_MAP: { [key: string]: number } = {
  'btv4k': 91417,  // 北京卫视4K
  'sh4k': 96050,   // 东方卫视4K
  'js4k': 95925,   // 江苏卫视4K
  'zj4k': 96039,   // 浙江卫视4K
  'sd4k': 95975,   // 山东卫视4K
  'hn4k': 96038,   // 湖南卫视4K
  'gd4k': 93733,   // 广东卫视4K
  'sc4k': 95965,   // 四川卫视4K
  'sz4k': 93735,   // 深圳卫视4K
};

// 频道名称映射
const CHANNEL_NAMES: { [key: string]: string } = {
  'btv4k': '北京卫视4K',
  'sh4k': '东方卫视4K',
  'js4k': '江苏卫视4K',
  'zj4k': '浙江卫视4K',
  'sd4k': '山东卫视4K',
  'hn4k': '湖南卫视4K',
  'gd4k': '广东卫视4K',
  'sc4k': '四川卫视4K',
  'sz4k': '深圳卫视4K',
};

// 简单的内存缓存（Edge Runtime中有效期为请求周期）
const cache = new Map<string, { value: string; expires: number }>();

/**
 * 获取访问token
 */
async function getToken(): Promise<string | null> {
  // 检查缓存
  const cached = cache.get('visitor_token');
  if (cached && cached.expires > Date.now()) {
    return cached.value;
  }

  const timeMillis = Date.now();
  const sign = await makeSign(API_URL1, '', timeMillis, AES_KEY);

  try {
    const response = await fetch(API_URL1, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'headers': '1.1.3',
        'sign': sign,
      },
    });

    if (!response.ok) return null;

    const data = await response.json();
    if (!data?.success || !data?.data?.token) return null;

    const token = data.data.token;
    // 缓存24小时
    cache.set('visitor_token', { value: token, expires: Date.now() + 86400000 });

    return token;
  } catch (error) {
    console.error('Get token error:', error);
    return null;
  }
}

/**
 * 获取频道数据
 */
async function getColumnData(token: string): Promise<any> {
  // 检查缓存
  const cached = cache.get('column_all_list_33');
  if (cached && cached.expires > Date.now()) {
    return JSON.parse(cached.value);
  }

  const columnId = 350;
  const params = new URLSearchParams({
    columnId: columnId.toString(),
    token: token,
  });

  const timeMillis = Date.now();
  const sign = await makeSign(API_URL2, params.toString(), timeMillis, AES_KEY);

  try {
    const response = await fetch(API_URL2, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'okhttp/3.11.0',
        'sign': sign,
      },
      body: params.toString(),
    });

    if (!response.ok) return null;

    const data = await response.json();
    if (!data?.success) return null;

    // 缓存10分钟
    cache.set('column_all_list_33', {
      value: JSON.stringify(data),
      expires: Date.now() + 600000,
    });

    return data;
  } catch (error) {
    console.error('Get column data error:', error);
    return null;
  }
}

/**
 * 在数据中查找播放地址
 */
function findPlayUrl(dataArr: any, targetId: number): string | null {
  if (!dataArr?.data || !Array.isArray(dataArr.data)) {
    return null;
  }

  // 遍历数据数组查找目标频道
  for (const item of dataArr.data) {
    // 检查 item.mediaAsset.id 和 item.mediaAsset.url
    if (item?.mediaAsset?.id === targetId && item?.mediaAsset?.url) {
      return item.mediaAsset.url;
    }
  }

  return null;
}

/**
 * 生成签名（AES-256-ECB加密）
 * Edge Runtime中使用Web Crypto API实现真正的ECB模式
 * ECB模式 = 对每个16字节块独立加密（不使用IV）
 */
async function makeSign(url: string, params: string, timeMillis: number, key: string): Promise<string> {
  const payload = {
    url: url,
    params: params,
    time: timeMillis,
  };

  const json = JSON.stringify(payload);

  // Convert key to CryptoKey
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt']
  );

  // Prepare data with PKCS7 padding
  const data = encoder.encode(json);
  const blockSize = 16;
  const paddingLength = blockSize - (data.length % blockSize);
  const paddedData = new Uint8Array(data.length + paddingLength);
  paddedData.set(data);
  for (let i = data.length; i < paddedData.length; i++) {
    paddedData[i] = paddingLength;
  }

  // Implement ECB by encrypting each block independently
  const numBlocks = paddedData.length / blockSize;
  const encryptedBlocks: Uint8Array[] = [];

  for (let i = 0; i < numBlocks; i++) {
    const block = paddedData.slice(i * blockSize, (i + 1) * blockSize);
    
    // Use zero IV for each block to simulate ECB
    const zeroIV = new Uint8Array(blockSize);
    
    const encryptedBlock = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: zeroIV },
      cryptoKey,
      block
    );
    
    // Take only the first 16 bytes (the encrypted block)
    encryptedBlocks.push(new Uint8Array(encryptedBlock).slice(0, blockSize));
  }

  // Concatenate all encrypted blocks
  const totalLength = encryptedBlocks.reduce((sum, block) => sum + block.length, 0);
  const encrypted = new Uint8Array(totalLength);
  let offset = 0;
  for (const block of encryptedBlocks) {
    encrypted.set(block, offset);
    offset += block.length;
  }

  // Base64 encode
  let binary = '';
  for (let i = 0; i < encrypted.length; i++) {
    binary += String.fromCharCode(encrypted[i]);
  }
  return btoa(binary).replace(/[\r\n]/g, '');
}

/**
 * 获取播放地址
 */
async function getPlayUrl(id: string): Promise<string | null> {
  if (!CHANNEL_MAP[id]) {
    return null;
  }

  // 获取token
  const token = await getToken();
  if (!token) {
    return null;
  }

  // 获取频道列表数据
  const dataArr = await getColumnData(token);
  if (!dataArr) {
    return null;
  }

  // 查找播放地址
  const targetId = CHANNEL_MAP[id];
  return findPlayUrl(dataArr, targetId);
}


/**
 * 获取并代理 m3u8 内容
 */
async function getM3u8Content(m3u8Url: string, baseUrl: string, channelId: string): Promise<string | null> {
  try {
    const response = await fetch(m3u8Url, {
      headers: {
        'Referer': 'https://api.chinaaudiovisual.cn/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
    });

    if (!response.ok) {
      return null;
    }

    let content = await response.text();
    
    // 获取 m3u8 的 base URL (用于处理相对路径)
    const m3u8BaseUrl = m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1);
    const urlObj = new URL(m3u8Url);
    const protocol = urlObj.protocol.replace(':', '');
    const host = urlObj.host;

    // 替换 ts 文件路径为代理路径
    // 匹配完整的 ts 行，包括可能的查询参数
    content = content.replace(/^(.*?\.ts[^\s]*)$/gim, (match) => {
      let tsUrl = match.trim();
      
      if (tsUrl.startsWith('http://') || tsUrl.startsWith('https://')) {
        // 已经是完整 URL
        // 不做处理
      } else if (tsUrl.startsWith('/')) {
        // 绝对路径，拼接协议和域名
        tsUrl = `${urlObj.protocol}//${urlObj.host}${tsUrl}`;
      } else {
        // 相对路径，拼接 baseUrl
        tsUrl = m3u8BaseUrl + tsUrl;
      }
      
      // 编码 ts URL
      const encodedTs = encodeURIComponent(tsUrl);
      return `${baseUrl}?id=${channelId}&ts=${encodedTs}`;
    });

    return content;
  } catch (error) {
    console.error('Failed to get m3u8 content:', error);
    return null;
  }
}

/**
 * 代理 TS 切片
 */
async function proxyTsSegment(tsUrl: string): Promise<Response> {
  try {
    const response = await fetch(tsUrl, {
      headers: {
        'Referer': 'https://api.chinaaudiovisual.cn/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
    });

    if (!response.ok) {
      return new NextResponse('TS segment not found', { status: 404 });
    }

    const headers = new Headers({
      'Content-Type': 'video/MP2T',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
    });

    return new NextResponse(response.body, {
      status: 200,
      headers,
    });
  } catch (error) {
    console.error('Failed to proxy TS segment:', error);
    return new NextResponse('Failed to fetch TS segment', { status: 500 });
  }
}

/**
 * 生成播放列表
 */
function generatePlaylist(baseUrl: string): string {
  let m3u = '#EXTM3U\n';
  for (const [id, channel] of Object.entries(CHANNELS)) {
    m3u += `#EXTINF:-1,${channel.name}\n`;
    m3u += `${baseUrl}/api/4k?id=${id}\n`;
  }
  return m3u;
}

/**
 * GET请求处理
 */
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id') || 'btv4k';

  // 如果是list请求，返回频道列表
  if (id === 'list') {
    let m3u8Content = '#EXTM3U\n';
    
    // 获取真实域名
    const host = getRealHost(request);
    const protocol = request.url.startsWith('https') ? 'https' : 'http';
    const baseUrl = `${protocol}://${host}/api/4k`;

    for (const [cid, _] of Object.entries(CHANNEL_MAP)) {
      const channelName = CHANNEL_NAMES[cid];
      m3u8Content += `#EXTINF:-1,${channelName}\n`;
      m3u8Content += `${baseUrl}?id=${cid}\n`;
    }

    return new NextResponse(m3u8Content, {
      headers: {
        'Content-Type': 'application/vnd.apple.mpegurl',
        'Cache-Control': 'public, max-age=3600',
      },
    });
  }

  // 获取播放地址
  const playUrl = await getPlayUrl(id);

  if (!playUrl) {
    return new NextResponse(`Channel not found: ${id}`, {
      status: 404,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }

  // 获取并代理 m3u8 内容
  const m3u8Content = await getM3u8Content(playUrl, baseUrl, id);
  if (!m3u8Content) {
    return new NextResponse('无法获取m3u8内容', {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }

  // 返回代理后的 m3u8
  return new NextResponse(m3u8Content, {
    headers: {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache',
    },
  });
}
