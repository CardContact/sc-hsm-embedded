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
 * @fileoverview SmartCard-HSM PKCS11 Tests
 */

load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

load("tools/eccutils.js");
// load("../ca/ca.js");


// Define test parameter
var param = new Array();
param["pin"] = "648219";
param["sopin"] = "3537363231383830";


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



function getSlot(p) {
	var slots = p.getSlots();

	var slot;
	for (var i = 0; i < slots.length; i++) {
		var s = slots[i];
	
		if (s.isRemovableDevice()) {
			if (s.isTokenPresent()) {
				return (s.getId());
			}
		}
	}
	return 0;
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


/*
function getPrivateKey(s, id) {
	// Enumerate public and private objects
	var objs = s.enumerateObjects();
	
//	print("Objects listed in R/O user session:");
	for (var i = 0; i < objs.length; i++) {
		var o = objs[i];
		var cl = o.getNumberAttribute(PKCS11Object.CKA_CLASS);
//		print("Class :" + str4class(cl));
		
		var kid = o.getAttribute(PKCS11Object.CKA_ID);
//		if (kid != null) {
//			print(" Id     :" + kid.toString(HEX));
//		}
		var label = o.getAttribute(PKCS11Object.CKA_LABEL);
//		if (label != null) {
//			print(" Label :" + label.toString(ASCII));
//		}
		if ((cl == PKCS11Object.CKO_PRIVATE_KEY) && (kid.equals(id))) {
//			print("Matching private key: " + label.toString(UTF8));
			return o;
		}
	}
	return null;
}



function getCertificate(s, id) {
	// Enumerate public and private objects
	var objs = s.enumerateObjects();
	
//	print("Objects listed in R/O user session:");
	for (var i = 0; i < objs.length; i++) {
		var o = objs[i];
		var cl = o.getNumberAttribute(PKCS11Object.CKA_CLASS);
//		print("Class :" + str4class(cl));
		
		var kid = o.getAttribute(PKCS11Object.CKA_ID);
//		if (kid != null) {
//			print(" Id     :" + kid.toString(HEX));
//		}
		var label = o.getAttribute(PKCS11Object.CKA_LABEL);
//		if (label != null) {
//			print(" Label :" + label.toString(ASCII));
//		}
		if ((cl == PKCS11Object.CKO_CERTIFICATE) && (kid.equals(id))) {
//			print("Matching certificate: " + label.toString(UTF8));
			return o;
		}
	}
	return null;
}
*/


function generateRSAKeyPair(s, label, keysize) {

	var priAttr = new Array();
	priAttr[PKCS11Object.CKA_TOKEN] = true;
	priAttr[PKCS11Object.CKA_SIGN] = true;
	priAttr[PKCS11Object.CKA_DECRYPT] = true;
	priAttr[PKCS11Object.CKA_UNWRAP] = true;
	priAttr[PKCS11Object.CKA_SENSITIVE] = true;
	priAttr[PKCS11Object.CKA_PRIVATE] = true;
	priAttr[PKCS11Object.CKA_LABEL] = label;

	var pubAttr = new Array();
	pubAttr[PKCS11Object.CKA_TOKEN] = true;
	pubAttr[PKCS11Object.CKA_VERIFY] = true;
	pubAttr[PKCS11Object.CKA_ENCRYPT] = true;
	pubAttr[PKCS11Object.CKA_WRAP] = true;
	pubAttr[PKCS11Object.CKA_MODULUS_BITS] = keysize;
	pubAttr[PKCS11Object.CKA_PUBLIC_EXPONENT] = new ByteString("010001", HEX);
	pubAttr[PKCS11Object.CKA_LABEL] = label;

	var keys = s.generateKeyPair(PKCS11Session.CKM_RSA_PKCS_KEY_PAIR_GEN, null, pubAttr, priAttr);

	var pub = keys[0];

	var cl = pub.getNumberAttribute(PKCS11Object.CKA_CLASS);
	print("Class  : " + str4class(cl));

	var kid = pub.getAttribute(PKCS11Object.CKA_ID);
	print(" Id    : " + kid.toString(HEX));

	var label = pub.getAttribute(PKCS11Object.CKA_LABEL);
	print(" Label : " + label.toString(ASCII));

	var value = pub.getAttribute(PKCS11Object.CKA_VALUE);
	print(" Value : " + value.toString(HEX));

	var pk = new ASN1(value);
	print(pk);
	var key = new Key();
	key.setType(Key.PUBLIC);
	key.setComponent(Key.MODULUS, pk.get(0).value);
	key.setComponent(Key.EXPONENT, pk.get(1).value);
	return key;
}



function generateECCKeyPair(s, label, curve) {

	var curveoid = new ByteString(curve, OID);
	var curveasn = new ASN1(ASN1.OBJECT_IDENTIFIER, curveoid);
	
	var priAttr = new Array();
	priAttr[PKCS11Object.CKA_TOKEN] = true;
	priAttr[PKCS11Object.CKA_SIGN] = true;
	priAttr[PKCS11Object.CKA_SENSITIVE] = true;
	priAttr[PKCS11Object.CKA_PRIVATE] = true;
	priAttr[PKCS11Object.CKA_LABEL] = label;

	var pubAttr = new Array();
	pubAttr[PKCS11Object.CKA_TOKEN] = true;
	pubAttr[PKCS11Object.CKA_VERIFY] = true;
	pubAttr[PKCS11Object.CKA_EC_PARAMS] = curveasn.getBytes();
	pubAttr[PKCS11Object.CKA_LABEL] = label;

	var keys = s.generateKeyPair(PKCS11Session.CKM_EC_KEY_PAIR_GEN, null, pubAttr, priAttr);

	var pub = keys[0];

	var cl = pub.getNumberAttribute(PKCS11Object.CKA_CLASS);
	print("Class  : " + str4class(cl));

	var kid = pub.getAttribute(PKCS11Object.CKA_ID);
	print(" Id    : " + kid.toString(HEX));

	var label = pub.getAttribute(PKCS11Object.CKA_LABEL);
	print(" Label : " + label.toString(ASCII));

	var value = pub.getAttribute(PKCS11Object.CKA_VALUE);
	print(" Value : " + value.toString(HEX));

	var pk = new ASN1(value);
	print(pk);
	var point = pk.value.bytes(1);
	
	var key = new Key();
	key.setType(Key.PUBLIC);
	key.setComponent(Key.ECC_CURVE_OID, curveoid);
	key.setComponent(Key.ECC_QX, point.left(point.length >> 1));
	key.setComponent(Key.ECC_QY, point.right(point.length >> 1));
	return key;
}



function storeCertificate(s, label, cert) {
	var attr = new Array();
	attr[PKCS11Object.CKA_CLASS] = PKCS11Object.CKO_CERTIFICATE;
	attr[PKCS11Object.CKA_CERTIFICATE_TYPE] = 0;  // CKC_X_509
	attr[PKCS11Object.CKA_TOKEN] = true;
	attr[PKCS11Object.CKA_LABEL] = label;
	attr[PKCS11Object.CKA_VALUE] = cert.getBytes();

	var o = new PKCS11Object(s, attr);

	return o;
}



function issueCertificate(ca, s, cn, keysizeOrCurve, profile) {
	var label = cn;
	var subject = [ { C:"DE" }, { O:"CardContact" }, { OU:"CardContact Demo CA 1" }, { CN:cn } ];

	print("Generating key pair for " + cn);
	if (typeof(keysizeOrCurve) == "string") {
		var publicKey = generateECCKeyPair(s, label, keysizeOrCurve);
	} else {
		var publicKey = generateRSAKeyPair(s, label, keysizeOrCurve);
	}
	
	if (typeof(keysizeOrCurve) == "string") {
		publicKey.setComponent(Key.ECC_CURVE_OID, new ByteString(keysizeOrCurve, OID));
	}
	
	var extvalues = { email : emailaddress };
	print("Issuing certificate for " + cn);
	var cert = ca.issueCertificate(publicKey, subject, profile, extvalues);
	print(cert);

	storeCertificate(s, label, cert);
}



var testRunner = new TestRunner("SmartCard-HSM PKCS#11 Tests");
testRunner.addTestGroupFromXML("tg_enumerate.xml", param);
//testRunner.addTestGroupFromXML("tg_initialize.xml", param);
//testRunner.addTestGroupFromXML("tg_generatekeys.xml", param);
//testRunner.addTestGroupFromXML("tg_certificate.xml", param);
testRunner.addTestGroupFromXML("tg_signing.xml", param);
testRunner.addTestGroupFromXML("tg_decryption.xml", param);
//testRunner.addTestGroupFromXML("tg_dataobjects.xml", param);
//testRunner.addTestGroupFromXML("tg_delete.xml", param);


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


