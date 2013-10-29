/**
 *  ---------
 * |.##> <##.|  SmartCard-HSM Support Scripts
 * |#       #|  
 * |#       #|  Copyright (c) 2011-2012 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 * Consult your license package for usage terms and conditions.
 * 
 * @fileoverview STARCOS PKCS11 Tests
 */

load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

load("tools/eccutils.js");
// load("../ca/ca.js");


// Define test parameter
var param = new Array();
param["pin"] = "123456";
param["sopin"] = "3537363231383830";
param["testkey"] = "C.CH.AUT";

param["provider"] = "/usr/local/lib/pkcs11-spy.so";
// param["provider"] = "/usr/local/lib/opensc-pkcs11.so";
// param["provider"] = "/home/asc/projects/sc-hsm-embedded/src/pkcs11/.libs/libsc-hsm-pkcs11.so";
// param["provider"] = "c:\\windows\\system32\\opensc-pkcs11.dll";
// param["provider"] = "C:\\Programme\\OpenSC Project\\PKCS11-Spy\\pkcs11-spy.dll";

// Some default value - need to be adjusted
var name = "Joe Doe";
var emailaddress = "joe.doe@openehic.org";



//
// Dump information about slot
//
function dumpSlotInfo(s) {

	print("Slot #" + s.getId());
	print(" Description       : " + s.getDescription());
	print(" Manufacturer      : " + s.getManufacturer());
	print(" Hardware Version  : " + s.getHardwareVersion());
	print(" Firmware Version  : " + s.getFirmwareVersion());
	print(" isTokenPresent    : " + s.isTokenPresent());
	print(" isHardwareDevice  : " + s.isHardwareDevice());
	print(" isRemovableDevice : " + s.isRemovableDevice());
	
	if (s.isTokenPresent()) {
		var label = s.getTokenLabel();

		print("  Token :");
		print("  Label                     : " + label);
		print("  Manufacturer              : " + s.getTokenManufacturer());
		print("  Model                     : " + s.getTokenModel());
		print("  Serial Number             : " + s.getTokenSerialNumber());
		print("  Max PIN Length            : " + s.getTokenMaxPinLen());
		print("  Min PIN Length            : " + s.getTokenMinPinLen());
		print("  hasTokenProtectedAuthPath : " + s.hasTokenProtectedAuthPath());
		
		var mechs = s.getMechanisms();
		for (var j = 0; j < mechs.length; j++) {
			print("   Mechanisms #" + j);
			var m = mechs[j];
			print("   Type         : " + m.getType() + " (" + m.getTypeName() + ")");
			print("   Min Key Size : " + m.getMinKeySize());
			print("   Max Key Size : " + m.getMaxKeySize());
			print("   Flags        : " + m.getFlags());
		}
	}
}



//
// Return a name for a PKCS#11 class
//
function str4class(c) {
	var str = "Unknown(" + c + ")";
	switch(c) {
	case PKCS11Object.CKO_DATA: str = "CKO_DATA"; break;
	case PKCS11Object.CKO_CERTIFICATE: str = "CKO_CERTIFICATE"; break;
	case PKCS11Object.CKO_PUBLIC_KEY: str = "CKO_PUBLIC_KEY"; break;
	case PKCS11Object.CKO_PRIVATE_KEY: str = "CKO_PRIVATE_KEY"; break;
	case PKCS11Object.CKO_SECRET_KEY: str = "CKO_SECRET_KEY"; break;
	case PKCS11Object.CKO_HW_FEATURE: str = "CKO_HW_FEATURE"; break;
	case PKCS11Object.CKO_DOMAIN_PARAMETERS: str = "CKO_DOMAIN_PARAMETERS"; break;
	case PKCS11Object.CKO_MECHANISM: str = "CKO_MECHANISM"; break;
	}
	return str;
}



function getSlot(p, token) {
	var slots = p.getSlots();

	var slot;
	for (var i = 0; i < slots.length; i++) {
		var s = slots[i];
	
		if (s.isRemovableDevice()) {
			if (s.isTokenPresent()) {
				if (token.equals(s.getTokenLabel())) {
					return (s.getId());
				}
			}
		}
	}
	return -1;
}



function getObjectByLabel(s, clazz, label) {
	// Enumerate public and private objects
	var objs = s.enumerateObjects();
	
//	print("Objects listed in R/O user session:");
	for (var i = 0; i < objs.length; i++) {
		var o = objs[i];
		var cl = o.getNumberAttribute(PKCS11Object.CKA_CLASS);
//		print("Class :" + str4class(cl));
		if (cl != clazz) {
			continue;
		}
		
		var lab = o.getAttribute(PKCS11Object.CKA_LABEL);
		if (lab != null) {
			var labelstr = lab.toString(ASCII);
//			print(" Label :" + labelstr);
			if (labelstr == label) {
				return o;
			}
		}
	}
	return null;
}


var testRunner = new TestRunner("STARCOS PKCS#11 Tests");
testRunner.addTestGroupFromXML("tg_enumerate.xml", param);
testRunner.addTestGroupFromXML("tg_signing.xml", param);
testRunner.addTestGroupFromXML("tg_signing_qes.xml", param);
testRunner.addTestGroupFromXML("tg_decryption.xml", param);


// Create and initialize simple CA
var crypto = new Crypto();
/*
var ca = new X509CA(crypto);

var fn = GPSystem.mapFilename("../ca/DEMO-CA.jks", GPSystem.CWD);
var ks = new KeyStore("SUN", "JKS", fn, "openscdp");
var key = new Key();
key.setID("DEMOCA");

ks.getKey(key, "openscdp");
ca.setSignerKey(key);

var cert = ks.getCertificate("DEMOCA");
ca.setSignerCertificate(cert);

param["ca"] = ca;
param["crypto"] = crypto;
*/
print("Test-Suite loaded...");


