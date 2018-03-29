var ClientEnrollCertFunc = null;
function PFXStore() {
  this.store = {};
}

PFXStore.prototype.load = function(name){
	var storages = localStorage.getItem(name);
	this.store = JSON.parse(storages)||{};
	this.name=name;
}
PFXStore.prototype.clear = function(){
	this.store = {};
	/*if(this.name) {
		localStorage.removeItem(this.name);
		this.name=null;
	}*/
}
PFXStore.prototype.save = function(name){
	name=name||this.name;
	return localStorage.setItem(name, JSON.stringify(this.store));
}
PFXStore.prototype.put = function(pfxb64, password){
	var pfx = pfxparse(pfxb64, password);
	//console.log('pfx', pfx);
	//var cert = parsecert(pfx.cert);
	//console.log('pfx.cert', pfx.cert);
	var iss_sn = pfx.cert.issuer.hash + "_" + pfx.cert.serialNumber;
	/*if(!pfxobject["pfx"]){
		//error object
	}else{
		var md = forge.md.md5.create();
		md.update(pfxobject["pfx"]);
		var index = md.digest().toHex();
		this.store[index] = pfxobject;
	}*/
	this.store[iss_sn] = {"cert":parsecert(pfx.cert), "pfx":pfxb64};
	//console.log('this', this);
}
function DNmatch(DN, query){//{"OU":"test","CN":"A123456789"}
	var allfound = true;
	for(var key in query){
		//console.log('key', key);
		//console.log('query[key]', query[key]);
		var reg = new RegExp(query[key]);
		var found = false;
		for(var attr in DN){
			//console.log('attr', attr);
			//console.log('cert.subject[attr]', DN[attr]);
			if(DN[attr].name===key && reg.test(DN[attr].value)){
				found=true;
				break;
			}
		}
		if(!found){
			allfound = false;
			break;
		}
	}
	return allfound;
}
PFXStore.prototype.query = function(queryattr){
	var result=[];
	
	for(var key in this.store){
	  //console.log('this.store[key]', this.store[key]);
      var match = true;
	  for(var attr in queryattr){
		//console.log('queryattr[attr]', queryattr[attr]);
		if(attr==='subject'){
		  if(!DNmatch(this.store[key].cert.subject, queryattr[attr])){
			  match = false;
			  break;
		  }
		}else if(attr==='issuer'){
		  if(!DNmatch(this.store[key].cert.issuer, queryattr[attr])){
			  match = false;
			  break;
		  }
		}else{//grp, tok...etc
			if(!(this.store[key].cert[attr] === queryattr[attr])){
			  match = false;
			  break;
			}
		}
	  }
	  if(match)
		  result.push(this.store[key]);
	}
	return result;
}
PFXStore.prototype.allpfxs = function(){
	var result=[];
	for(var key in this.store){
		result.push(this.store[key]);
	}
	return result;
}
PFXStore.prototype.remove = function(queryattr){
	for(var key in this.store){
	  //console.log('this.store[key]', this.store[key]);
      var match = true;
	  for(var attr in queryattr){
		//console.log('queryattr[attr]', queryattr[attr]);
		if(attr==='subject'){
		  if(!DNmatch(this.store[key].cert.subject, queryattr[attr])){
			  match = false;
			  break;
		  }
		}else if(attr==='issuer'){
		  if(!DNmatch(this.store[key].cert.issuer, queryattr[attr])){
			  match = false;
			  break;
		  }
		}else{//grp, tok...etc
			if(!(this.store[key].cert[attr] === queryattr[attr])){
			  match = false;
			  break;
			}
		}
	  }
	  if(match)
		  delete this.store[key];
	}
}
var keys = null;
function SyncKeyGen(){
	keys = forge.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001});
	if(keys){
		if(console) console.log('SyncKeyGen ok');
	}else{
		if(console) console.error('SyncKeyGen fail');
	}	
}
function AsyncKeyGen(csrfunc, callback){
	if (window.Worker) {
		forge.pki.rsa.generateKeyPair({bits: 2048, workers: -1, workerScript: 'js6/prime.worker.js'}, csrfunc);
	}else{
		if(console) console.log('web Worker is not supported! Try to generate an RSA key pair synchronously!');
		SyncKeyGen();
		//return keys;
	}
}

//var cert = null;
//var pfxb64;
function genCSR_internal(err, keypair){
	if(err){
		if(console) console.error(err);
		if(console) console.error('Error! Try to generate an RSA key pair synchronously!');
		SyncKeyGen();
	}else{
		if(console) console.log('AsyncKeyGen ok');
		keys = keypair;
	}
	if(!keys){
		if(console) console.error("can't gen key");
		if(ClientEnrollCertFunc){
			ClientEnrollCertFunc(null);
		}
		return;
	}
	var csr = forge.pki.createCertificationRequest();
	csr.publicKey = keys.publicKey;
	csr.setSubject([{
	  name: 'commonName',
	  value: 'Pubca User'
	}, {
	  name: 'countryName',
	  value: 'TW'
	}]);

	// sign certification request
	csr.sign(keys.privateKey);
	//if(console) console.log('csr',csr);
	var csr64 = forge.util.encode64(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes());
	if(console) console.log('csr64',csr64);
	//return csr64;
	if(ClientEnrollCertFunc){
		ClientEnrollCertFunc(csr64);
	}
	//enrollCert(csr64);
}
function genKeyAndCSR(callback){
	ClientEnrollCertFunc = callback;
	AsyncKeyGen(genCSR_internal);
}
function genPFX(cert, pwd, key){
	if (key === undefined || key === null) {
          key = keys.privateKey;
    } 
	if(!key){
		if(console) console.error("no key");
		return null;
	}
	if(!cert){
		if(console) console.error("no cert");
		return null;
	}
	// generate a p12 that can be imported by Chrome/Firefox/iOS
	// (requires the use of Triple DES instead of AES)
	var p12Asn1 = forge.pkcs12.toPkcs12Asn1(
	  key, [cert], pwd,
	  {algorithm: '3des'});
	  
	// base64-encode p12
	var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
	//console.log(typeof p12Der);
	var pfxb64 = forge.util.encode64(p12Der);
	//if(console) console.log('pfxb64', pfxb64);
	return pfxb64;
	//localStorage.setItem("MyPFX", pfxb64);
	//alert("申請憑證成功!")
	//location.reload();
}
function changePassword(pfxb64, old_pwd, new_pwd){
	var pfx = pfxparse(pfxb64, old_pwd);
	var newpfxb64 = genPFX(pfx.cert, new_pwd, pfx.key);
	return newpfxb64;
}
function parsecert(cert){
	//document.getElementById("certs").value = "";
	
	var attrs = cert.subject.attributes;
	var certSubject = "";
	var subject = [];
	for(var attrindex in attrs){
		if(certSubject.length > 0) certSubject+=", "
		certSubject += attrs[attrindex].shortName+"="+attrs[attrindex].value;
		var name=attrs[attrindex].shortName?attrs[attrindex].shortName:attrs[attrindex].type;
		subject.push({"name":name,"value":attrs[attrindex].value});
	}
	
	attrs = cert.issuer.attributes;
	var certIssuer = "";
	var issuer = [];
	for(var attrindex in attrs){
		if(certIssuer.length > 0) certIssuer+=", "
		certIssuer += attrs[attrindex].shortName+"="+attrs[attrindex].value;
		var name=attrs[attrindex].shortName?attrs[attrindex].shortName:attrs[attrindex].type;
		issuer.push({"name":name,"value":attrs[attrindex].value});
	}
	
	
	var ret={};
	//ret.sub=certSubject;
	ret.subject=subject;
	//ret.iss=certIssuer;
	ret.issuer=issuer;
	ret.sn=cert.serialNumber;
	ret.nbf=cert.validity.notBefore.toJSON();
	ret.nat=cert.validity.notAfter.toJSON();
	
	var subDirAttrs = cert.getExtension({"name":"subjectDirectoryAttributes"});
	//console.log(subDirAttrs);
	if(subDirAttrs){
		var subDirAttrsValue = forge.asn1.fromDer(subDirAttrs.value);
		//console.log('subDirAttrsValue',subDirAttrsValue);
		if(subDirAttrsValue.value instanceof Array){
			for(var index in subDirAttrsValue.value){
				var attribute = subDirAttrsValue.value[index];
				//console.log('attribute',attribute);
				if(attribute.value instanceof Array && attribute.value.length===2){
					var attrtype = forge.asn1.derToOid(attribute.value[0].value);
					//console.log('attrtype',attrtype);
					if(attrtype==='2.16.886.1.100.2.204'){
						ret.tok = attribute.value[1].value[0].value;
					}else if(attrtype==='2.16.886.1.100.2.200'){
						ret.grp = forge.asn1.derToInteger(attribute.value[1].value[0].value);
					}else if(attrtype==='2.16.886.1.100.2.201'){
						ret.typ = forge.asn1.derToInteger(attribute.value[1].value[0].value);
					}else if(attrtype==='2.16.886.1.100.2.202'){
						ret.uid = attribute.value[1].value[0].value;
					}else if(attrtype==='2.16.886.1.100.2.51'){
						ret.idt = attribute.value[1].value[0].value;
					}
				}
			}
		}
	}
	
	var subAltName = cert.getExtension({"name":"subjectAltName"});
	if(subAltName){
		var altNames = subAltName.altNames;
		if(altNames instanceof Array){
			for(var index in altNames){
				var altName = altNames[index];
				if(altName.type===1){
					if(ret.eml && (ret.eml instanceof Array)){
						ret.eml.push(altName.value);
					}else{
						ret.eml = [altName.value];
					}
				}else if(altName.type===2){
					if(ret.dns && (ret.dns instanceof Array)){
						ret.dns.push(altName.value);
					}else{
						ret.dns = [altName.value];
					}
				}
			}
		}
	}
	
	return ret;
}
function pfxparse(pfxb64, password){
	var pfxder = forge.util.decode64(pfxb64);
	//console.log("p12Der ok");
	p12Asn1 = forge.asn1.fromDer(pfxder, false);
	
	//console.log("p12Asn1 ok");
	
	try{
		p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
	}catch(e){
		if(console) console.error(e);
		return;
	}
	//pfxb64 = _arrayBufferToBase64(arrayBuffer);
	//console.log(p12);
	
	var keybags = p12.getBags({bagType: forge.pki.oids.pkcs8ShroudedKeyBag});
	// get key
	//console.log(keybags);
	if(keybags[forge.pki.oids.pkcs8ShroudedKeyBag].length <= 0){
		alert("no key");
		return;
	}
	var keybag = keybags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
	pfxkey = keybag.key;
	
	//console.log('pfxkey',pfxkey);
	
	var certbags = p12.getBags({bagType: forge.pki.oids.certBag});
	//console.log(certbags);
	if(certbags[forge.pki.oids.certBag].length <= 0){
		alert("no cert");
		return;
	}
	
	// bags are key'd by bagType and each bagType key's value
	// is an array of matches (in this case, certificate objects)
	var certbag = certbags[forge.pki.oids.certBag][0];
	pfxusercert = certbag.cert;
	
	return {"key":pfxkey, "cert":pfxusercert};
}
function p7sign(key, cert, detached){
	if (detached === undefined || detached === null) {
          detached = false;
    } 
	
	var p7 = forge.pkcs7.createSignedData();
	p7.content = forge.util.createBuffer(document.getElementById("tbs").value, 'utf8');
	p7.addCertificate(pfxusercert);
	p7.addSigner({
	  key: key,
	  certificate: cert,
	  digestAlgorithm: forge.pki.oids.sha256,
	  authenticatedAttributes: []
	});
	if(detached){
		p7.signDetached();
	}else{
		p7.sign();
	}
	
	//if(console) console.log(p7);
	//var pem = forge.pkcs7.messageToPem(p7);
	//console.log(pem);
	var p7asn = p7.toAsn1();
	//console.log(p7asn);
	
	var p7der = forge.asn1.toDer(p7asn);
	//console.log(p7der);
	var p7b64 = forge.util.encode64(p7der.getBytes());
	
	return p7b64;
}
var epkirootpem="-----BEGIN CERTIFICATE-----\
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\
hNQ+IIX3Sj0rnP0qCglN6oH4EZw=\
-----END CERTIFICATE-----";
var pubcapem="-----BEGIN CERTIFICATE-----\
MIIFaTCCA1GgAwIBAgIRAMlT/u64lekYhKuyKmikKn0wDQYJKoZIhvcNAQEFBQAw\
XjELMAkGA1UEBhMCVFcxIzAhBgNVBAoMGkNodW5naHdhIFRlbGVjb20gQ28uLCBM\
dGQuMSowKAYDVQQLDCFlUEtJIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw\
HhcNMDcwNTE2MTAxMzU1WhcNMjcwNTE2MTAxMzU1WjBbMQswCQYDVQQGEwJUVzEj\
MCEGA1UECgwaQ2h1bmdod2EgVGVsZWNvbSBDby4sIEx0ZC4xJzAlBgNVBAsMHlB1\
YmxpYyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQAD\
ggEPADCCAQoCggEBAJbEUbRogBe+Unld424LbzivM4pQdCnV/uNe7S2287+9fqCx\
njtKfxni/HzwTiShxGlaWcz9oXnnBVgizU1IkGn3U1vbJMaMgOX1CbCYNdj0atYf\
KuxRmtQfPAP6BmUVF74w5znjDJhzWO0wm15xsx+fhb89HzqUDV9gC9aK1LKgoAFh\
Ii8nbGxrKEhZchZlzIHNMxQGgdcAJLUCI5EToKh3/xHWv/KCRJVXOD11AtLmwMdB\
HxGNhIeOUpax0sHRmescUi76tqGp3PDsKz53C2ysLsBf4FykiQSrfKEqyLg+Rxk6\
6ultf41cQLAm4+WwXIvxwqtGEGuoEWNWXdylREsCAwEAAaOCASMwggEfMB8GA1Ud\
IwQYMBaAFB4M97Zn8uGSJglFwFU5Lnc/QkqiMB0GA1UdDgQWBBRxs1AxoBtbe7Km\
WXz9EIw8rTo9ejAOBgNVHQ8BAf8EBAMCAQYwKgYDVR0gBCMwITAJBgdghnYBZAAB\
MAkGB2CGdgFkAAIwCQYHYIZ2AWQAAzASBgNVHRMBAf8ECDAGAQH/AgEAMDkGA1Ud\
HwQyMDAwLqAsoCqGKGh0dHA6Ly9lcGtpLmNvbS50dy9yZXBvc2l0b3J5L0NSTC9D\
QS5jcmwwUgYIKwYBBQUHAQEERjBEMEIGCCsGAQUFBzAChjZodHRwOi8vZXBraS5j\
b20udHcvcmVwb3NpdG9yeS9DZXJ0cy9Jc3N1ZWRUb1RoaXNDQS5wN2IwDQYJKoZI\
hvcNAQEFBQADggIBACCs4ZeBiuv4TX4BOZJnyq6AH6Aq3yAojLj/NbU1O0wMI5y+\
qufAxXSCSAnwrdBwAADzYTt5NTBORkkm7q7P1eQlmvT6iqQaIDkpdJsZFjgHQS6a\
8xBzT3d5+Sm3jEIQoDFgQ1/E6vBepBLXmrkdSd7NZ8QbEY19ggHNniOreycShkMb\
UqX5uG1jyvOHuHzsa1BcLQWh2l1myoxTz2X+jJ5f04fmpveVZgb+CxUyMvCQE4Ac\
wMFU59fxZ8Wkggp6H9bkVrRzXJdS0Su2xK7z5AEW5sf6BbNj8WnfmOejP1nakQdJ\
B+tEPDlmHtisV8yu0dopN9Z2tbx9aDxMlO1MrKF21bzN2nzl+NTaJ/8wEqVSbtNs\
UIVV9+eLgbOcrqcfnZgD5aWQVEpvaiBAZqzZGLA/luc+0w2QbqpiZlGAF4Qi4/a0\
QbGFsNLCXaZW0ioH/kFmTuL2NSVg2zz2xqhFv+k6GNI4amZqz/eEEk1yBQkX1apc\
oz+MRgh8khNYZAVIllEhI78o1nKZYDAFY8lQ28b57GmsMi90M9buIfvQnBf0ly/B\
wGXo/Xpw1mP1oNJCbC/AlfI+Gkfnch/k+SQ5z9Jmwf3ELoY0fE2BxzD49hHDQ+Ah\
Eeyg+X04q/lrynYbxNJoBBQugIiv0GDzzzuNh4FAMWfEAeKf/xck3ABAgNLb\
-----END CERTIFICATE-----";
var pubcag2pem="-----BEGIN CERTIFICATE-----\
MIIF8DCCA9igAwIBAgIRAMQj0iGRho+sTuL85KAR0acwDQYJKoZIhvcNAQELBQAw\
XjELMAkGA1UEBhMCVFcxIzAhBgNVBAoMGkNodW5naHdhIFRlbGVjb20gQ28uLCBM\
dGQuMSowKAYDVQQLDCFlUEtJIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw\
HhcNMTQxMjExMDg1MTU5WhcNMzQxMjExMDg1MTU5WjBgMQswCQYDVQQGEwJUVzEj\
MCEGA1UECgwaQ2h1bmdod2EgVGVsZWNvbSBDby4sIEx0ZC4xLDAqBgNVBAsMI1B1\
YmxpYyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEcyMIIBIjANBgkqhkiG9w0B\
AQEFAAOCAQ8AMIIBCgKCAQEA6GW/UWo7X8suYIMHqHozBGkyigC12vLP0jv5OjWh\
9m+eYM90gTGs8llp/K11J3Zv/7dByYmxP5lic21CoZjMbaDjwi+aBk3ZMSrDRHCK\
oEp1ECIXOB0bk31XCzUu+jGBOh6S5Q8xl+QX1aiHX83vmP09jJu8Qb7cbuPEkvaa\
Fe/QbD+8O4SFAKO4CwYZ6LzSymihXIv256JNuEf7p+zyh+R9VJYQr4bEsrjLzAi+\
6ZHmp9AmDvrnEyGewqG87s6RrYbcZbfa0kfV6cxymex0q/vw8/4vlBunkOaaRbPo\
DyEEGQCgblrQjcClvuihHyfpCM+GKiT/2FaS3htEVee4OQIDAQABo4IBpTCCAaEw\
HwYDVR0jBBgwFoAUHgz3tmfy4ZImCUXAVTkudz9CSqIwHQYDVR0OBBYEFMuDfWUV\
r6nJ86ip9GR8eVIFdEBhMA4GA1UdDwEB/wQEAwIBBjBABgNVHR8EOTA3MDWgM6Ax\
hi9odHRwOi8vZWNhLmhpbmV0Lm5ldC9yZXBvc2l0b3J5L0NSTF9TSEEyL0NBLmNy\
bDCBiwYIKwYBBQUHAQEEfzB9MEQGCCsGAQUFBzAChjhodHRwOi8vZWNhLmhpbmV0\
Lm5ldC9yZXBvc2l0b3J5L0NlcnRzL0lzc3VlZFRvVGhpc0NBLnA3YjA1BggrBgEF\
BQcwAYYpaHR0cDovL29jc3AuZWNhLmhpbmV0Lm5ldC9PQ1NQL29jc3BHMXNoYTIw\
EgYDVR0TAQH/BAgwBgEB/wIBADBrBgNVHSAEZDBiMA0GCysGAQQBgbcjZAABMA0G\
CysGAQQBgbcjZAACMA0GCysGAQQBgbcjZAADMAkGB2CGdgFkAAEwCQYHYIZ2AWQA\
AjAJBgdghnYBZAADMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcNAQELBQAD\
ggIBAG+egEUMXXGhkQKIkBk0B/byxk8eyJJwwhJIh+KlPSnQU6CCOMtlp/nikEWD\
hDvVBzdW78XtPeUHIFHaBSPCN1Q8eF26HU/tgs4SQAssLkQvG/EGw1azsaQAvHfm\
Z7l+Gm6i8YNREPYsov+kYGVG2ekD32Bna9iYPx6LAGRZLUR7IUxG78qN78kkcmLv\
4NfJcMs1kIJ4SluLh7bT8yl9bcJP/0o++2J7tNLrYIVLMK/v84/mm4VqcLwggLC1\
qUSTz5ftSf+TXjUw2GH3uMtZ940nj/5z/l/23XOVyu4fKmvaJM1a3yQmrLaLxsxU\
RkS15+agpC/jQjZ4XouirwhiUIBAGrs2Q+/W2Z4OY+cKHrNnqlFX5kivRhKNdwRv\
sw/ODZxvsnSVxgZawEZHE3cDQYS3bUYh+UHTFBpKf8mKCyHXL6WJ6cqeYPY0xMLy\
AkP0Dbuw0j7x1deYEeFy1kpzWBtiEQeWsXt2ijtF0Ig//B+04OBF9ySdGEOC4ALI\
OEQkNdNPeUigZNIYKc9B8+8rsxe1W+Cv6Qx+M3NDchXjXP1W39le4n9hzAJ9iHGg\
gunVc1CgRmKhY/3Du6z21xDK1Xez4A+s+DGzN5rCjWkfxu9eWNsIjzTtCs9TKF7R\
S+ehk1McUDqNkkD57i6QPiKMTv5A1i2UXyFuJCG43FWLwmIA\
-----END CERTIFICATE-----";
var pubcatestpem="-----BEGIN CERTIFICATE-----\
MIIFFDCCAvygAwIBAgIRAJuHL6j6tiuxCeWUa0vT15IwDQYJKoZIhvcNAQEFBQAw\
TTELMAkGA1UEBhMCVFcxIzAhBgNVBAoMGkNodW5naHdhIFRlbGVjb20gQ28uLCBM\
dGQuMRkwFwYDVQQLDBBlQ0FfUm9vdENBX2F0X1RMMB4XDTA3MTAzMDAyMDkzMVoX\
DTE3MTAzMDAyMDkzMVowWzELMAkGA1UEBhMCVFcxIzAhBgNVBAoMGkNodW5naHdh\
IFRlbGVjb20gQ28uLCBMdGQuMScwJQYDVQQLDB5QdWJsaWNDQSBmb3IgVGVzdGlu\
Zyhzb2Z0d2FyZSkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoKieC\
O02eksfyBI+xO305dSGQ+Li671LbWOKAGaNWrkKCqoVif7D0tBFE9jp2ZI6yD8i8\
n+Ebq0hxDGeQffoKk10PcLWDBcLDcFCw5yPyGo9P5AssrklYktLjDOYGcH+6m5ox\
ctEUM/SyM8fJaRAM9rXPnvNfRg1GoVFIi2GX/6AIb/ubBPv30BAUeOyUNN9vgnCs\
3cKPU0CCBkwI1N6ruH1CSN1noucqThA8X5/TSSg4eI2Erj9gP3Ca3KiTLDfy85jP\
0b2tcFQt47HUOEXWIW/N9MzjwXG6MJYXqAluMrhVE+QI+AlzJj+60Lju6zs3Bn6R\
opjQUVpa5UGwQKudAgMBAAGjgeAwgd0wHwYDVR0jBBgwFoAUximBktkOVtwnCxiy\
xiAXBec1FCEwHQYDVR0OBBYEFO0yxvx7Z1CkF9q64XIcJYwRqv/yMA4GA1UdDwEB\
/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6\
Ly82MS4yMjAuMjI0LjI3L2VDQS9DUkwvQ0EuY3JsMEQGCCsGAQUFBwEBBDgwNjA0\
BggrBgEFBQcwAoYoaHR0cDovLzYxLjIyMC4yMjQuMjcvZUNBL0NlcnQvUm9vdENB\
LnA3YjANBgkqhkiG9w0BAQUFAAOCAgEAGmmNqQaLJQ1rlsZrZhNBIwlEkmXYtKzB\
8ghvSp10PlSd5ECPx5nsOQD23a+8FWm199Fgy8F1fkmOsThyiPYgUrtCl5LmGjka\
hqZ7uAkNeRNam8OoY1t3/hOazcFgHvYhWnHtWGGGqT8SjJQGJXx+N+Rv0jeTDUHP\
WJbMbZY/v7NI3LKWrxyptppqYLAivcbF1azSXc2vF/OmFPgo0Occy43aedYCJF+l\
LPzHOG4JtJv+4bVoH/LRsJ7rQ0UuloRdmeUKcOgcQxieK5oyMyanyqj3H2dz9lIh\
VhNalCPAua2Aaj9irsJn7ZUSeyTsfPsNCE4WT65UlhIDUJEW2mhDpBw0XWtxNoci\
S/qQ7gyYgbR5GveGyJj0UV5CZkqe9vmihGPGxBOiPe91/b+WlPxDDkzOOWQYRytU\
UQfPLaxIxSU8DhG1spN/IVOGFltzvST6nV+01P2Dh5CFQXkAEniP4H8wEd9+4jbE\
khUgo3StWOgu1swqPAjNXl0v1dYryYUSsfYGo3SYOnCsqdiTZF0tyCoyY+g2pCBD\
dr9jPERMhFE13dzVj50fsXEFPXXF195FfYQf7qrvzoyaciQSjrwk/0b+irc4YxVm\
lADS8gefkMQLwpi2ns1QuC1UZLqnI2ve3Hw+K6LliByAkAQCTwmNhk501UO57VAa\
jkd/zaRc/aY=\
-----END CERTIFICATE-----";
var pubcag2 = forge.pki.certificateFromPem(pubcag2pem);
var pubca = forge.pki.certificateFromPem(pubcapem);
var epkiroot = forge.pki.certificateFromPem(epkirootpem);
var pubcatest = forge.pki.certificateFromPem(pubcatestpem);
	//console.log(pubcag2);
	//var cer = forge.pki.certificateFromPem(CHILD_CERTIFICATE);
	// verify certificate
var caStore = forge.pki.createCaStore();
	//caStore.addCertificate(pfxusercert);
caStore.addCertificate(pubca);
caStore.addCertificate(pubcag2);
caStore.addCertificate(epkiroot);
caStore.addCertificate(pubcatest);