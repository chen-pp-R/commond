package com.cmpay.dicp.agw.filter;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.cmpay.dicp.agw.client.IAccessSecretService;
import com.cmpay.dicp.agw.constants.SignConstants;
import com.cmpay.dicp.agw.dto.SecretInfoDTO;
import com.cmpay.lemon.common.LemonConstants;
import com.cmpay.lemon.common.utils.DateTimeUtils;
import com.cmpay.lemon.common.utils.JudgeUtils;
import com.netflix.zuul.context.RequestContext;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;

import static com.cmpay.dicp.agw.constants.SignConstants.REQUEST_HEADER_SIGN;
import static com.cmpay.dicp.agw.filter.AccessLogFilter.*;
import static com.netflix.zuul.context.RequestContext.getCurrentContext;
import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.POST_TYPE;
import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_DECORATION_FILTER_ORDER;

/**
 * 签名验签样例
 *
 * @author he_lsh
 * @since 2021-08-23 16:07:12
 */
public class demo {
    //签名
    public void sign() {
        String requestBody = "{\n    \"appName\": \"我是一个json\"}";
        String appid = "分配应用id --需要放到请求头当中";
        String xLemonSecure = "分配的行业客户编号 --需要放到请求头当中";
        String signVerifyValue = "分配的签名校验值（盐）";
        String privateKey = "签名私钥";
        String publicKey = "我方提供的验签公钥";
        RSA rsa = new RSA(privateKey, publicKey);
        AES aes = new AES(SecureUtil.decode("加密密钥"));
        //1. 请求报文加密
        String requestEncryptBody = aes.encryptBase64(requestBody);
        //2.获取当前时间戳等签名参数
        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        String signSource = requestEncryptBody + signVerifyValue + now;
        //3.签名 --需要放到请求头当中
        String sign = rsa.encryptBase64(SecureUtil.md5(signSource), KeyType.PrivateKey);
        //4.设置请求头参数
        HashMap<String, String> header = new HashMap<>();
        header.put("app-id", appid);
        header.put("x-lemon-sign", sign);
        header.put("x-lemon-secure", xLemonSecure);
        header.put("tm-smp", now);
        header.put("x-sign-type", "rsa-md5-tm");
        header.put("Content-Type", "text/plain;charset=utf-8");
        //5.将requestEncryptBody作为请求体报文
    }
    //验签
    public void verifySign() {
        String requestEncryptBody = "加密aes密文";
        String signVerifyValue = "分配的签名校验值（盐）";
        String privateKey = "签名私钥";
        String publicKey = "我方提供的验签公钥";
        HttpServletRequest request = null;
        RSA rsa = new RSA(privateKey, publicKey);
        AES aes = new AES(SecureUtil.decode("加密密钥"));
        String md5 = SecureUtil.md5(requestEncryptBody + signVerifyValue + "从请求头里面获取的时间戳");
        String sign = request.getHeader("x-lemon-sign");
        byte[] decrypt = rsa.decrypt(SecureUtil.decode(sign), KeyType.PublicKey);
        String decryptSign = new String(decrypt);
        //验签
        if (!StringUtils.equalsIgnoreCase(md5, decryptSign)) {
            //验签失败
            return;
        }
        //报文解密得到解密报文
        String requestBody = aes.decryptStr(requestEncryptBody);
    }
}
