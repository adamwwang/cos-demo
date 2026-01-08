// 临时密钥服务例子
require('dotenv').config(); // 加载 .env 文件
var express = require('express');
var crypto = require('crypto');
var moment = require('moment');

// 配置参数
var config = {
    // 获取腾讯云密钥，建议使用限定权限的子用户的密钥 https://console.cloud.tencent.com/cam/capi
    secretId: process.env.SecretId,
    secretKey: process.env.SecretKey,
    // 这里填写存储桶、地域，例如：test-1250000000、ap-guangzhou
    bucket: process.env.Bucket,
    region: process.env.Region,
    // 限制的上传后缀
	extWhiteList: ['jpg', 'jpeg', 'png', 'gif', 'bmp'],
};

// 生成要上传的 COS 文件路径文件名
var generateCosKey = function (ext) {
	var ymd = moment().format('YYYYMMDD');
	var timestamp = moment().format('HHmmss');
	var r = ('000000' + Math.random() * 1000000).slice(-6);
	var cosKey = `images/${ymd}/IMG_${ymd}_${timestamp}_${r}.${ext}`;
	return cosKey;
};

// 创建临时密钥服务和用于调试的静态服务
var app = express();
// PUT Object 接口签名生成
// 签名文档：https://cloud.tencent.com/document/product/436/7778
app.all('/put-policy', function (req, res, next) {
	var ext = req.query.ext;
    // 判断异常情况
    if (!config.secretId || !config.secretKey) return res.send({code: '-1', message: 'secretId or secretKey not ready'});
    if (!config.bucket || !config.region) return res.send({code: '-1', message: 'bucket or regions not ready'});
    if (!config.extWhiteList.includes(ext)) return res.send({code: '-1', message: 'ext not allow'});
    
    // 开始计算凭证
	var cosHost = `${config.bucket}.cos.${config.region}.myqcloud.com`;
	var cosKey = generateCosKey(ext);
    var now = Math.round(Date.now() / 1000);
    var exp = now + 900; // 15分钟有效期
    var qKeyTime = now + ';' + exp;
    var qSignAlgorithm = 'sha1';
    
    // 步骤一：生成 SignKey
    var signKey = crypto.createHmac('sha1', config.secretKey).update(qKeyTime).digest('hex');
    
    // 步骤二：生成 HttpString（PUT Object 的请求信息）
    var httpMethod = 'put';
    var httpURI = '/' + cosKey;
    var httpParameters = '';
    var httpHeaders = '';
    var httpString = httpMethod + '\n' + httpURI + '\n' + httpParameters + '\n' + httpHeaders + '\n';
    
    // 步骤三：生成 StringToSign
    var stringToSign = qSignAlgorithm + '\n' + qKeyTime + '\n' + crypto.createHash('sha1').update(httpString).digest('hex') + '\n';
    
    // 步骤四：生成 Signature
    var qSignature = crypto.createHmac('sha1', signKey).update(stringToSign).digest('hex');
    
    // 步骤五：拼接最终的 Authorization
    var authorization = [
        'q-sign-algorithm=' + qSignAlgorithm,
        'q-ak=' + config.secretId,
        'q-sign-time=' + qKeyTime,
        'q-key-time=' + qKeyTime,
        'q-header-list=',
        'q-url-param-list=',
        'q-signature=' + qSignature
    ].join('&');
    
    // 生成访问文件的签名（GET 请求，用于下载/预览）
    var getExpire = now + 3600; // 1小时有效期
    var getKeyTime = now + ';' + getExpire;
    var getSignKey = crypto.createHmac('sha1', config.secretKey).update(getKeyTime).digest('hex');
    var getHttpString = 'get\n/' + cosKey + '\n\n\n';
    var getStringToSign = qSignAlgorithm + '\n' + getKeyTime + '\n' + crypto.createHash('sha1').update(getHttpString).digest('hex') + '\n';
    var getSignature = crypto.createHmac('sha1', getSignKey).update(getStringToSign).digest('hex');
    var getAuthorization = [
        'q-sign-algorithm=' + qSignAlgorithm,
        'q-ak=' + config.secretId,
        'q-sign-time=' + getKeyTime,
        'q-key-time=' + getKeyTime,
        'q-header-list=',
        'q-url-param-list=',
        'q-signature=' + getSignature
    ].join('&');
    
    // 返回域名、文件路径、签名信息
    res.setHeader('Content-Type', 'application/json');
    res.send({
        cosHost: cosHost,
        cosKey: cosKey,
        authorization: authorization,
        getUrl: `https://${cosHost}/${cosKey}?${getAuthorization}`, // 带签名的访问链接
        // securityToken: securityToken, // 如果使用临时密钥，需要返回 sessionToken
    });
});
app.all('*', function (req, res, next) {
    res.send({code: -1, message: '404 Not Found'});
});

// 启动签名服务
app.listen(3000);
console.log('app is listening at http://127.0.0.1:3000');
