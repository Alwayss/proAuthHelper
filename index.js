var fs = require('fs');
var os = require('os');
var crypto = require('crypto');
var readline = require('readline');
var RSA = require('node-rsa');
var getPem = require('rsa-pem-from-mod-exp');
var parser = require('xml2json');
var path = require('path');

function ProAuthHelper() {

}

/**
 * 获取设备硬件码
 */
ProAuthHelper.prototype.getMachineCode = function () {
    var cpuId = os.cpus()[0].model;                           //第一个cpu模型名称
    var hostname = os.hostname();                             //主机名代替主板ID
    var sys = os.platform();                                  //操作系统
    var hardwareCode = cpuId + hostname + sys;
    return GetMD5Hash(hardwareCode,'hex');                           //获取机器码
};

/**
 * dir: 生成.dat存储的位置
 * options(object): 文件内容
 * callback: 回调函数
 */
ProAuthHelper.prototype.createDatFile = function (dir, options, callback) {
    var fileDir = path.resolve(dir, new Date().getTime() + '.dat');
	  var that = this;
    if (typeof options !== "object") {
        var err = new Error('the options must be object');
        return callback(err);
    }
    for (var p in options) {
        fs.appendFileSync(fileDir, options[p] + '\r\n');
    }
    fs.appendFileSync(fileDir, that.getMachineCode() + '\r\n');
    callback(null, { msg: 'the file Have been generated' });
};

/**
 * 检验license有效性
 * dir: license文件路径
 * callback: 回调函数
 */
ProAuthHelper.prototype.checkLicenseInfo = function (dir, PubKey, callback) {
    var that = this;
    if (!fs.existsSync(dir)) {
        var err = new Error('the file is nonexiest');
        return callback(err);
    }
 
    ReadFileByLine(dir, function (data) {
        var licenseInfo = GetLicenseInfo(data);
        licenseInfo.PubKey = PubKey;
        var now = new Date().getTime();
        var endTime = new Date(licenseInfo.ExpirationTime).getTime();
        if(now > endTime){
            return callback(null, {code: 'time',msg: 'Authorization expired'});
        }
        var str = licenseInfo.ProductID + that.getMachineCode() + licenseInfo.Cooperation + licenseInfo.ExpirationTime  + licenseInfo.Type;
        var licenseCode = licenseInfo.LicenseCode;

        // 获取对应的公钥
        var json = JSON.parse(parser.toJson(licenseInfo.PubKey));
        var modulus = json.RSAKeyValue.Modulus;
        var exponent = json.RSAKeyValue.Exponent;
        var pem = getPem(modulus, exponent);
        var publicPem = new RSA(pem);
        var publicKey = publicPem.exportKey('public');

				// 加签
        var verifier = crypto.createVerify('sha1');
        verifier.update(new Buffer(str),'base64');

        var bool = verifier.verify(publicKey, new Buffer(licenseCode,'base64'),'base64');
        if(bool){
            callback(null, {code: 'ok'});
        }else{
            callback(null, {code: 'machine',msg: 'The current machine is not authorized'});
        }
        
    });
};

function GetMD5Hash(text,encoding) {
    return crypto.createHash('md5').update(Buffer.from(text)).digest(encoding);
}

function GetLicenseInfo(array) {
    var licenseInfo = {};
    var tag = array[0].slice(0,1);
    var pattern = /[^a-zA-Z0-9]/;
    if(pattern.test(tag)){
      licenseInfo.ProductID = array[0].slice(1);
    }else{
      licenseInfo.ProductID = array[0];
    }
    licenseInfo.ProductName = array[1];
    licenseInfo.Cooperation = array[3];
    licenseInfo.Partner = array[2];
    // licenseInfo.PubKey = array[4];
	  licenseInfo.Type = array[4];
    licenseInfo.LicenseCode = array[6];
    licenseInfo.ExpirationTime = array[5];
    return licenseInfo;
}

function ReadFileByLine(dir, callback) {
    var array = [];
    var rl = readline.createInterface({
        input: fs.createReadStream(dir, 'utf8')
    });
    rl.on('line', function (line) {
        array.push(line);
    });
    rl.on('close', function () {
        callback(array);
    })
}

module.exports = ProAuthHelper;