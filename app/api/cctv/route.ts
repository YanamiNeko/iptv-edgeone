import { NextRequest, NextResponse } from 'next/server';
import { getRealHost } from '../utils/url';
import { aes128CbcDecrypt, hmacSha256 } from '../utils/crypto';

export const runtime = 'edge';

// 频道配置：[liveRoomNumber, secretKey, 名称]
const CHANNELS: Record<string, [string, string, string]> = {
  'cctv1': ['11200132825562653886', '0916dc838fce69425b9aed6d3e790f49', 'CCTV1'],
  'cctv2': ['12030532124776958103', '102ebab86b52dcb7d437aa64cac55223', 'CCTV2'],
  'cctv4': ['10620168294224708952', 'bbb5af21098ef891310f3e95aca7eaa0', 'CCTV4'],
  'cctv7': ['8516529981177953694', '7c4f4b447ac8cac73ad13949ef59c322', 'CCTV7'],
  'cctv9': ['7252237247689203957', '59c85627b6aa0e7ee013fe51b3666f35', 'CCTV9'],
  'cctv10': ['14589146016461298119', 'c4f615635b5c4476b16bf0492e3b9539', 'CCTV10'],
  'cctv12': ['13180385922471124325', '8e254cbff89764a5a2a034d710d82af1', 'CCTV12'],
  'cctv13': ['16265686808730585228', '563e1000aabda6bdda96248302d34051', 'CCTV13'],
  'cctv17': ['4496917190172866934', '0aad8b82812bb4f20bbbec854b278525', 'CCTV17'],
  'cctv4k': ['2127841942201075403', '29d4d53e67ee9881362d686aa959d3e9', 'CCTV4K'],
};

// 清晰度配置（resolution_id）
const QUALITY_MAP: Record<string, number> = {
  'lg': 1005,  // 蓝光 1080P
  'cq': 1004,  // 超清 720P  
  'gq': 1003,  // 高清 480P
};

// 解密URL
async function decryptUrl(authUrl: string, dk: string, xReqTs: string): Promise<string> {
  const key = getKey(dk, xReqTs);
  const iv = getIv(dk, xReqTs);
  return await aes128CbcDecrypt(authUrl, key, iv);
}

// 生成密钥
function getKey(dk: string, xReqTs: string): string {
  const timestamp = xReqTs.substring(0, xReqTs.length - 3);
  return dk.substring(0, 8) + timestamp.substring(timestamp.length - 8);
}

// 生成IV
function getIv(dk: string, xReqTs: string): string {
  const timestamp = xReqTs.substring(0, xReqTs.length - 3);
  return dk.substring(dk.length - 8) + timestamp.substring(0, 8);
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get('id');
    const q = searchParams.get('q') || 'lg';

    // 频道列表
    if (id === 'list') {
      const host = getRealHost(request);
      const protocol = request.url.startsWith('https') ? 'https' : 'http';
      const baseUrl = `${protocol}://${host}/api/cctv`;
      
      let m3u8 = '#EXTM3U\n';
      for (const [channelId, [, , name]] of Object.entries(CHANNELS)) {
        m3u8 += `#EXTINF:-1,${name}\n`;
        m3u8 += `${baseUrl}?id=${channelId}&q=${q}\n`;
      }

      return new NextResponse(m3u8, {
        headers: {
          'Content-Type': 'application/vnd.apple.mpegurl',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    const channelId = id || 'cctv1';
    if (!CHANNELS[channelId]) {
      return new NextResponse('Invalid channel ID', { status: 400 });
    }

    const [liveRoomNumber, secretKey] = CHANNELS[channelId];
    const quality = QUALITY_MAP[q] ?? 0;

    // 构建请求参数
    const timestamp = Math.floor(Date.now() / 1000);
    const signContent = `&&&20000009&${secretKey}&${timestamp}&emas.feed.article.live.detail&1.0.0&&&&&`;
    const appKey = 'emasgatewayh5';
    const sign = await hmacSha256(signContent, appKey);

    const apiUrl = `https://emas-api.cctvnews.cctv.com/h5/emas.feed.article.live.detail/1.0.0?articleId=${liveRoomNumber}&scene_type=6`;
    const xReqTs = `${timestamp}123`;
    const clientId = '274109e8075742b58b7bdd32c7e19e89';

    // 请求API
    const response = await fetch(apiUrl, {
      headers: {
        'cookieuid': clientId,
        'from-client': 'h5',
        'referer': 'https://m-live.cctvnews.cctv.com/',
        'x-emas-gw-appkey': '20000009',
        'x-emas-gw-pv': '6.1',
        'x-emas-gw-sign': sign,
        'x-emas-gw-t': timestamp.toString(),
        'user-agent': 'Mozilla/5.0 (Windows NT 6.1)',
        'x-req-ts': xReqTs,
      },
    });

    if (!response.ok) {
      return new NextResponse('API request failed', { status: 502 });
    }

    const data = await response.json();
    const responseData = JSON.parse(atob(data.response));
    const liveData = responseData.data;
    const pullUrlList = liveData.live_room.liveCameraList[0].pullUrlList;
    
    // 查找匹配清晰度的流，如果没找到就用第一个
    let streamInfo = pullUrlList.find((item: any) => item.resolution_id === quality);
    if (!streamInfo && pullUrlList.length > 0) {
      streamInfo = pullUrlList[0]; // 使用第一个可用的流
    }
    
    if (!streamInfo) {
      return new NextResponse('No stream available', { status: 404 });
    }
    
    let liveUrl = streamInfo.authResultUrl[0].authUrl;

    // 如果URL是加密的，需要解密
    if (!liveUrl.startsWith('http')) {
      const dk = liveData.dk;
      liveUrl = await decryptUrl(liveUrl, dk, xReqTs);
    }

    //// 替换为http协议并去掉-hls
    //liveUrl = liveUrl.replace('https:', 'http:').replace('-hls.', '.');
    liveUrl = liveUrl.replace('https:', 'http:');

    // 302跳转到实际的m3u8地址
    return NextResponse.redirect(liveUrl, 302);

  } catch (error) {
    console.error('CCTV API error:', error);
    if (error instanceof Error) {
      console.error('Error message:', error.message);
      console.error('Error stack:', error.stack);
    }
    return new NextResponse(`Internal Server Error: ${error}`, { status: 500 });
  }
}
