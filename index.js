var fs = require('fs');
var os = require('os');
var crypto = require('crypto');
var readline = require('readline');
var ursa = require('ursa');
var parser = require('xml2json');

function ProAuthHelper() {

}

/**
 * 获取设备硬件码
 */
ProAuthHelper.prototype.getMachineCode = function () {
    var cpuId = os.cpus()[0].model;                           //第一个cpu名称模型
    var hostname = os.hostname();                             //主机名代替主板ID
    var sys = os.platform();                                  //操作系统
    var hardwareCode = cpuId + hostname + sys;
    return GetMD5Hash(hardwareCode,'hex');                           //获取机器码
}

/**
 * dir: 生成.dat存储的位置
 * options(object): 文件内容
 * callback: 回调函数
 */
ProAuthHelper.prototype.createDatFile = function (dir, options, callback) {
    if (options instanceof Object) {
        var err = new Error('the options must be object');
        return callback(error);
    }
    for (var p in options) {
        fs.appendFileSync(dir, options[p] + '\n');
    }
    callback(null, { msg: 'the file Have been generated' });
}

/**
 * 检验license有效性
 * dir: license文件路径
 * callback: 回调函数
 */
ProAuthHelper.prototype.checkLicenseInfo = function (dir, callback) {
    var that = this;
    if (!fs.existsSync(dir)) {
        var err = new Error('the options must be object');
        return callback(error);
    }
 
    ReadFileByLine(dir, function (data) {
        var licenseInfo = GetLicenseInfo(data);
        var str = "3115b476-c342-4163-9e0a-68c04574d880" + licenseInfo.ExpirationTime + that.getMachineCode();
        console.log(str);
        var licenseCode = licenseInfo.LicenseCode;
        var json = JSON.parse(parser.toJson(licenseInfo.PubKey));
        var modulus = json.RSAKeyValue.Modulus;
        var exponent = json.RSAKeyValue.Exponent;
        var hashdata = GetMD5Hash(str,'base64');

        var publicKey = ursa.createPublicKeyFromComponents(new Buffer(modulus, 'base64'), new Buffer(exponent, 'base64'));
        var result = publicKey.verify('md5', new Buffer(hashdata, 'base64'), new Buffer(licenseCode, 'base64'));
        callback(null, result);
    });
}

function GetMD5Hash(text,encoding) {
    return crypto.createHash('md5').update(new Buffer(text)).digest(encoding);
}

function GetLicenseInfo(array) {
    var licenseInfo = {};
    licenseInfo.ProductID = array[0];
    licenseInfo.ProductName = array[1];
    licenseInfo.Partner = array[2];
    licenseInfo.Cooperation = array[3];
    licenseInfo.PubKey = array[4];
    licenseInfo.LicenseCode = array[5];
    licenseInfo.ExpirationTime = array[6];
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

// var helper = new ProAuthHelper();
// helper.checkLicenseInfo('C:\\Users\\admin\\Desktop\\产品认证\\fdff0156-19c7-4587-b709-c28603a208ec.lic', function(err,result){
//     console.log(result);
// });

module.exports = ProAuthHelper;