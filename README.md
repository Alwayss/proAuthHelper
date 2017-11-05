# proAuthHelper
product authorization helper

## dependencies
On Windows, you'll need to install some dependencies first:

- OpenSSL (normal, not light) in the same bitness as your Node.js installation.
- OpenSSL must be installed in the a specific install directory (C:\OpenSSL-Win32 or C:\OpenSSL-Win64)
- If you get Error: The specified module could not be found., copy libeay32.dll from the OpenSSL bin directory to this module's bin directory, or to Windows\System32.
- node-gyp (npm install -g node-gyp)
- You will need python 2.7 and a compatible version Visual Studio installed first. Even with that, node-gyp installation or use can have issues on Windows. The node-gyp README file has detailed instructions if you have difficulties. This post is also a good reference.


## Installing

```
npm install pro-auth-helper --save
```
> <sub>Requires nodejs >= 0.10.x</sub>

## Example

### 检验license文件有效性
* filepath — `{string}` — the xx.dat file path

    	var ProAuthHelper = require('pro-auth-helper');
    	var helper = new ProAuthHelper();
    			
    	helper.checkLicenseInfo(filepath, function(err,result){
    		console.log(result);
    	});

### 生成.dat文件
* filepath — `{string}` — the xx.dat file path
* data — `{object}` — then file content
* result — `{bool}` — the result of this check.

    	helper.createDatFile(filepath,data,function(err,result){
    			if(err) {
    			console.log(err);
    		}else{
    			console.log(result);
    		}
    	});
