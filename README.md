# proAuthHelper
product authorization helper

## Requirements
On Windows, you'll need to install some dependencies first:

- node-gyp (npm install -g node-gyp)
- python 2.7 and a compatible version Visual Studio installed first. Even with that, node-gyp installation or use can have issues on Windows. The node-gyp README file has detailed instructions if you have difficulties. This post is also a good reference.


## Installing

```
npm install pro-auth-helper --save
```
> <sub>Requires nodejs >= 0.10.x</sub>

## Example

    var ProAuthHelper = require('pro-auth-helper');
    var helper = new ProAuthHelper();


### 检验license文件有效性

* filepath — `{string}` — the xx.lic file path

    	helper.checkLicenseInfo(filepath, function(err, result){
    		console.log(result);
    	});

> result: {code: 'time',msg: 'Authorization expired'} or {code: 'machine',msg: 'The current machine is not authorized'} or {code: 'ok'}
### 生成.dat文件
* filepath — `{string}` — the xx.dat file path
* data — `{object}` — then file content
* result — `{bool}` — the result of this check.

    	helper.createDatFile(filepath, {produceId:xxx,username:xxxx,...}, function(err, result){
    		if(err) {
    			console.log(err);
    		}else{
    			console.log(result);
    		}
    	});
> result: { msg: 'the file Have been generated' }