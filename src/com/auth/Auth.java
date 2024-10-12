package com.auth;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.auth.utils.Base64Utils;
import com.auth.utils.BaseUtils;
import com.auth.utils.DES;
import com.auth.utils.SignUtil;
import okhttp3.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class Auth {

    private static String appkey = "";
    private static String appSecret = "";
    private static String token = "";
    private static String opToken = "opToken";
    private static String operator = "CMCC";

    public static void main(String[] args) throws Exception {
        String authHost = "http://identify-auth.zztfly.com/";
        String url = authHost + "auth/auth/sdkClientFreeLogin";
        HashMap<String, Object> request = new HashMap<>();
        request.put("appkey", appkey);
        request.put("token", token);
        request.put("opToken", opToken);
        request.put("operator", operator);
        request.put("timestamp", System.currentTimeMillis());
        request.put("sign", SignUtil.getSign(request, appSecret));
        String response = postRequestNoSecurity(url, null, request);

        JSONObject jsonObject = JSONObject.parseObject(response);
        if (200 == jsonObject.getInteger("status")) {
            String res = jsonObject.getString("res");
            byte[] decode = DES.decode(Base64Utils.decode(res.getBytes()), appSecret.getBytes());
            jsonObject.put("res", JSONObject.parseObject(new String(decode)));
        }
        System.out.println(jsonObject);
    }


    public static String postRequestNoSecurity(String url, Map<String, String> headers, Object data) throws Exception {
        String securityReq = JSON.toJSONString(data);
        OkHttpClient okHttpClient = new OkHttpClient.Builder().readTimeout(30, TimeUnit.SECONDS).build();
        RequestBody body = RequestBody.create(MediaType.parse("application/json"), securityReq);
        Request.Builder builder = new Request.Builder();
        if (!BaseUtils.isEmpty(headers)) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                builder.addHeader(entry.getKey(), entry.getValue());
            }
        }
        final Request request = builder.addHeader("Content-Length", String.valueOf(securityReq.length()))
                .url(url)
                .post(body)
                .build();
        Call call = okHttpClient.newCall(request);
        Response response = call.execute();

        String securityRes = response.body().string();
        return securityRes;
    }
}
