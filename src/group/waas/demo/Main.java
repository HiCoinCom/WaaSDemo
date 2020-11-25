package group.waas.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class Main {
	//在线生成RSA公私钥对 ：http://www.metools.info/code/c80.html 
	//推荐密码长度：2048
	//推荐密钥格式：PKCS#8

	public static String APPID = "申请的WaaS APPID";
	public static String priKeyDemo = "DEMO生成的私钥，用于加密请求的数据";
	public static String pubSys = "WaaS分配的公钥，用于解密返回数据";
	public static void main(String[] args) {

		//请求余额接口
		String respond = getBanlance();
		JSONObject o = (JSONObject) JSON.parse(respond);
		//获取返回结果 
		String encryptRespData= o.getString("data");
		
		// 解密响应数据,使用waas系统分配的分钥解密
		String decryptRespData = RSAHelper.decryptByPublicKey( encryptRespData,pubSys );
		System.out.println("decryptRespData:"+decryptRespData);
	}

	
	public static String getBanlance() {
		
		StringBuilder sb = new StringBuilder();
		sb.append("https://openapi.hicoin.vip/api/v2/account/getCompanyBySymbol?");
		sb.append(getBanlanceGetParams());
		
		
		String content = null;
		try {
			System.out.println("get Params:"+sb.toString());
			content = SimpleHttpUtils.get(sb.toString());
			System.out.println("content:"+content);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return content;
	}
	public static String getBanlanceGetParams() {
		String originReqData = "{time: 1603513079720, charset: \"utf8\", vesion: \"v2\", symbol: \"KRIS\"}";
		String encryptReqData = RSAHelper.encryptByPrivateKey(originReqData, priKeyDemo);
		return "app_id="+APPID+"&data=" + encryptReqData;
	}
}
