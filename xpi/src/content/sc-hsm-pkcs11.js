
var pkcsLoader = function (e) {
	var httpHandler = Components.classes["@mozilla.org/network/protocol;1?name=http"].getService(Components.interfaces.nsIHttpProtocolHandler);

	if (httpHandler.platform == "Windows") {
		var modName = "sc-hsm-pkcs11.dll";
	} else {
		var modName = "/usr/local/lib/libsc-hsm-pkcs11.so";
	}
	var P11 = Components.classes["@mozilla.org/security/pkcs11;1"].getService(Components.interfaces.nsIPKCS11);
	P11.addModule("SmartCard-HSM", [modName], 0x1 << 28, 0);
	//P11.addModule("SmartCard-HSM", ["/usr/local/lib/pkcs11-spy.so"], 0x1 << 28, 0);
}
window.addEventListener ("load", pkcsLoader, false);
