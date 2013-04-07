// Modified by Recurity Labs GmbH 

// modified version of http://www.hanewin.net/encrypt/PGdecode.js:

/* OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

// --------------------------------------
/**
 * This function encrypts a given with the specified prefixrandom 
 * using the specified blockcipher to encrypt a message
 * @param prefixrandom random bytes of block_size length provided 
 *  as a string to be used in prefixing the data
 * @param blockcipherfn the algorithm encrypt function to encrypt
 *  data in one block_size encryption. The function must be 
 *  specified as blockcipherfn([integer_array(integers 0..255)] 
 *  block,[integer_array(integers 0..255)] key) returning an 
 *  array of bytes (integers 0..255)
 * @param block_size the block size in bytes of the algorithm used
 * @param plaintext data to be encrypted provided as a string
 * @param key key to be used to encrypt the data as 
 *  integer_array(integers 0..255)]. This will be passed to the 
 *  blockcipherfn
 * @param resync a boolean value specifying if a resync of the 
 *  IV should be used or not. The encrypteddatapacket uses the 
 *  "old" style with a resync. Encryption within an 
 *  encryptedintegrityprotecteddata packet is not resyncing the IV.
 * @return a string with the encrypted data
 */
function openpgp_cfb_encrypt(prefixrandom, blockcipherencryptfn, plaintext, block_size, key, resync) {
	var FR = new Array(block_size);
	var FRE = new Array(block_size);

	prefixrandom = prefixrandom + prefixrandom.charAt(block_size-2) +prefixrandom.charAt(block_size-1);
	util.print_debug("prefixrandom:"+util.hexstrdump(prefixrandom));
	var ciphertext = "";
	// 1.  The feedback register (FR) is set to the IV, which is all zeros.
	for (var i = 0; i < block_size; i++) FR[i] = 0;
	
	// 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
    //     encryption of an all-zero value.
	FRE = blockcipherencryptfn(FR, key);
	// 3.  FRE is xored with the first BS octets of random data prefixed to
    //     the plaintext to produce C[1] through C[BS], the first BS octets
    //     of ciphertext.
	for (var i = 0; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ prefixrandom.charCodeAt(i));
	
	// 4.  FR is loaded with C[1] through C[BS].
	for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(i);
	
	// 5.  FR is encrypted to produce FRE, the encryption of the first BS
    // 	   octets of ciphertext.
	FRE = blockcipherencryptfn(FR, key);

	// 6.  The left two octets of FRE get xored with the next two octets of
	//     data that were prefixed to the plaintext.  This produces C[BS+1]
	//     and C[BS+2], the next two octets of ciphertext.
	ciphertext += String.fromCharCode(FRE[0] ^ prefixrandom.charCodeAt(block_size));
	ciphertext += String.fromCharCode(FRE[1] ^ prefixrandom.charCodeAt(block_size+1));

	if (resync) {
		// 7.  (The resync step) FR is loaded with C3-C10.
		for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(i+2);
	} else {
		for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(i);
	}
	// 8.  FR is encrypted to produce FRE.
	FRE = blockcipherencryptfn(FR, key);
	
	if (resync) {
		// 9.  FRE is xored with the first 8 octets of the given plaintext, now
	    //	   that we have finished encrypting the 10 octets of prefixed data.
	    // 	   This produces C11-C18, the next 8 octets of ciphertext.
		for (var i = 0; i < block_size; i++)
			ciphertext += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(i));
		for(n=block_size+2; n < plaintext.length; n+=block_size) {
			// 10. FR is loaded with C11-C18
			for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(n+i);
		
			// 11. FR is encrypted to produce FRE.
			FRE = blockcipherencryptfn(FR, key);
		
			// 12. FRE is xored with the next 8 octets of plaintext, to produce the
			// next 8 octets of ciphertext.  These are loaded into FR and the
			// process is repeated until the plaintext is used up.
			for (var i = 0; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt((n-2)+i));
		}
	}
	else {
		plaintext = "  "+plaintext;
		// 9.  FRE is xored with the first 8 octets of the given plaintext, now
	    //	   that we have finished encrypting the 10 octets of prefixed data.
	    // 	   This produces C11-C18, the next 8 octets of ciphertext.
		for (var i = 2; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(i));
		var tempCiphertext = ciphertext.substring(0,2*block_size).split('');
		var tempCiphertextString = ciphertext.substring(block_size);
		for(n=block_size; n<plaintext.length; n+=block_size) {
			// 10. FR is loaded with C11-C18
			for (var i = 0; i < block_size; i++) FR[i] = tempCiphertextString.charCodeAt(i);
			tempCiphertextString='';
			
			// 11. FR is encrypted to produce FRE.
			FRE = blockcipherencryptfn(FR, key);
			
			// 12. FRE is xored with the next 8 octets of plaintext, to produce the
			//     next 8 octets of ciphertext.  These are loaded into FR and the
			//     process is repeated until the plaintext is used up.
			for (var i = 0; i < block_size; i++){ tempCiphertext.push(String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(n+i)));
			tempCiphertextString += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(n+i));
			}
		}
		ciphertext = tempCiphertext.join('');
		
	}
	return ciphertext;
}

function openpgp_cfb_encrypt_large(prefixrandom, blockcipherencryptfn, plaintext, block_size, key, resync, progressCallback) {
	var FR = new Array(block_size);
	var FRE = new Array(block_size);
	//var saveConstant = 200000;
	var saveConstant = 300000;
	var mypos = 0;
	var blob = undefined;
	var length = plaintext.length;
	var ciphertext = new Uint8Array(34+block_size+(saveConstant*16));
	//var ciphertext = [];
	var cipherCount = 0;
	var tmpAfter = "";
	var tmpBefore = "";
	
	prefixrandom = prefixrandom + prefixrandom.charAt(block_size-2) +prefixrandom.charAt(block_size-1);
	util.print_debug("prefixrandom:"+util.hexstrdump(prefixrandom));
	self.debug("Plaintext length: " + plaintext.length + " cipher length: " + ciphertext.length);

	// 1.  The feedback register (FR) is set to the IV, which is all zeros.
	for (var i = 0; i < block_size; i++) FR[i] = 0;
	
	// 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
    //     encryption of an all-zero value.
	FRE = blockcipherencryptfn(FR, key);
	// 3.  FRE is xored with the first BS octets of random data prefixed to
    //     the plaintext to produce C[1] through C[BS], the first BS octets
    //     of ciphertext.
	//for (var i = 0; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ prefixrandom.charCodeAt(i));
	for (var i = 0; i < block_size; i++) ciphertext[mypos++] = FRE[i] ^ prefixrandom.charCodeAt(i);
	
	// 4.  FR is loaded with C[1] through C[BS].
	//for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(i);
	for (var i = 0; i < block_size; i++) FR[i] = ciphertext[i];
	
	// 5.  FR is encrypted to produce FRE, the encryption of the first BS
    // 	   octets of ciphertext.
	FRE = blockcipherencryptfn(FR, key);

	// 6.  The left two octets of FRE get xored with the next two octets of
	//     data that were prefixed to the plaintext.  This produces C[BS+1]
	//     and C[BS+2], the next two octets of ciphertext.
	ciphertext[mypos++] = FRE[0] ^ prefixrandom.charCodeAt(block_size);
	ciphertext[mypos++] = FRE[1] ^ prefixrandom.charCodeAt(block_size+1);
	
	self.debug("Resync: " + resync);
	
	if (resync) {
		// 7.  (The resync step) FR is loaded with C3-C10.
		for (var i = 0; i < block_size; i++) FR[i] = ciphertext[i+2];
	} else {
		for (var i = 0; i < block_size; i++) FR[i] = ciphertext[i];
	}
	// 8.  FR is encrypted to produce FRE.
	FRE = blockcipherencryptfn(FR, key);
	
	self.debug("Length so far: " + mypos);
	
	if (resync) {
		// 9.  FRE is xored with the first 8 octets of the given plaintext, now
	    //	   that we have finished encrypting the 10 octets of prefixed data.
	    // 	   This produces C11-C18, the next 8 octets of ciphertext.
		for (var i = 0; i < block_size; i++)
			ciphertext[mypos++] = FRE[i] ^ plaintext.get(i);
		
		self.debug("Length so far: " + mypos);
		
		var FRBlock = [];
		for(var i = block_size+2; i < (block_size+(block_size+2)); i++) FRBlock[i-(block_size+2)] = ciphertext[i];
		
		var counter = 0;
		var progressIndex = 0;
		
		self.debug("Starting for loop");
		var j = 0;
		for(n=block_size+2; n <= plaintext.length+1; n+=block_size) {
			
			// 10. FR is loaded with C11-C18
			for (var i = 0; i < block_size; i++) FR[i] = FRBlock[i];
			
			// 11. FR is encrypted to produce FRE.
			FRE = blockcipherencryptfn(FR, key);
			
			// 12. FRE is xored with the next 8 octets of plaintext, to produce the
			// next 8 octets of ciphertext.  These are loaded into FR and the
			// process is repeated until the plaintext is used up.
			FRBlock = [];
			for (var i = 0; i < block_size && ((n-2)+i) < plaintext.length ; i++) {
				plaintextVal = plaintext.get((n-2)+i);
				
				if(plaintextVal == undefined) {
					ciphertext[mypos++] = FRE[i] ^ 0;
				} else {
					//ciphertext[mypos++] = FRE[i] ^ plaintextVal.charCodeAt();
					ciphertext[mypos++] = FRE[i] ^ plaintextVal;
				}
				
				FRBlock[i] = ciphertext[mypos-1];
			}
			
			if(counter == saveConstant)
			{
				if(blob == undefined) {
					self.debug("Creating blob.");
					blob = new Blob([util.getArrayStoreFormat(ciphertext)], {type: 'application/octet-stream'})
				} else {
					blob = new Blob([blob, util.getArrayStoreFormat(ciphertext)], {type: 'application/octet-stream'})
				}
				
				// Calculate what's left
				if((plaintext.length-n) < ((saveConstant+1)*16)) {
					ciphertext = new Uint8Array((plaintext.length-n));
				} else {
					ciphertext = new Uint8Array(((saveConstant+1)*16));
				}
				cipherCount += mypos;
				mypos = 0;
				counter = 0;
			} else {
				counter++;
			}
			
			if((progressIndex%64000) == 0) {
				var percent = Math.round(((progressIndex/length) * 100)*Math.pow(10,2))/Math.pow(10,2);
				progressCallback(percent);
			}
			progressIndex+=block_size;
		}
		cipherCount += mypos;
		if(blob == undefined) {
			self.debug("Constructing new blob with length: " + cipherCount + " (" + ciphertext.length + ")");
			//var cipher = new Uint8Array(ciphertext);
			blob = new Blob([util.getArrayStoreFormat(ciphertext.subarray(0, cipherCount))], {type: 'application/octet-stream'});
			//blob = new Blob([cipher], {type: 'application/octet-stream'});
			self.debug("Result: " + blob.size);
		} else {
			blob = new Blob([blob, util.getArrayStoreFormat(ciphertext)], {type: 'application/octet-stream'});
		}
	}
	else {
		plaintext = "  "+plaintext;
		// 9.  FRE is xored with the first 8 octets of the given plaintext, now
	    //	   that we have finished encrypting the 10 octets of prefixed data.
	    // 	   This produces C11-C18, the next 8 octets of ciphertext.
		for (var i = 2; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(i));
		var tempCiphertext = ciphertext.substring(0,2*block_size).split('');
		var tempCiphertextString = ciphertext.substring(block_size);
		for(n=block_size; n<plaintext.length; n+=block_size) {
			// 10. FR is loaded with C11-C18
			for (var i = 0; i < block_size; i++) FR[i] = tempCiphertextString.charCodeAt(i);
			tempCiphertextString='';
			
			// 11. FR is encrypted to produce FRE.
			FRE = blockcipherencryptfn(FR, key);
			
			// 12. FRE is xored with the next 8 octets of plaintext, to produce the
			//     next 8 octets of ciphertext.  These are loaded into FR and the
			//     process is repeated until the plaintext is used up.
			for (var i = 0; i < block_size; i++){ tempCiphertext.push(String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(n+i)));
			tempCiphertextString += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(n+i));
			}
		}
		ciphertext = tempCiphertext.join('');
		
	}
	//var buff = new buffer(blob);
	var buff = new uint8ArrayBuffer(blob);
	self.debug("Cipher length: " + blob.size);
	self.debug("Cipher length: " + buff.length);
	
	return buff;
}

/**
 * decrypts the prefixed data for the Modification Detection Code (MDC) computation
 * @param blockcipherencryptfn cipher function to use
 * @param block_size blocksize of the algorithm
 * @param key the key for encryption
 * @param ciphertext the encrypted data
 * @return plaintext data of D(ciphertext) with blocksize length +2
 */
function openpgp_cfb_mdc(blockcipherencryptfn, block_size, key, ciphertext) {
	var iblock = new Array(block_size);
	var ablock = new Array(block_size);
	var i;

	// initialisation vector
	for(i=0; i < block_size; i++) iblock[i] = 0;

	iblock = blockcipherencryptfn(iblock, key);
	for(i = 0; i < block_size; i++)
	{
		ablock[i] = ciphertext.charCodeAt(i);
		iblock[i] ^= ablock[i];
	}

	ablock = blockcipherencryptfn(ablock, key);

	return util.bin2str(iblock)+
		String.fromCharCode(ablock[0]^ciphertext.charCodeAt(block_size))+
		String.fromCharCode(ablock[1]^ciphertext.charCodeAt(block_size+1));
}
/**
 * This function decrypts a given plaintext using the specified
 * blockcipher to decrypt a message
 * @param blockcipherfn the algorithm _encrypt_ function to encrypt
 *  data in one block_size encryption. The function must be 
 *  specified as blockcipherfn([integer_array(integers 0..255)] 
 *  block,[integer_array(integers 0..255)] key) returning an 
 *  array of bytes (integers 0..255)
 * @param block_size the block size in bytes of the algorithm used
 * @param plaintext ciphertext to be decrypted provided as a string
 * @param key key to be used to decrypt the ciphertext as 
 *  integer_array(integers 0..255)]. This will be passed to the 
 *  blockcipherfn
 * @param resync a boolean value specifying if a resync of the 
 *  IV should be used or not. The encrypteddatapacket uses the 
 *  "old" style with a resync. Decryption within an 
 *  encryptedintegrityprotecteddata packet is not resyncing the IV.
 * @return a string with the plaintext data
 */

function openpgp_cfb_decrypt(blockcipherencryptfn, block_size, key, ciphertext, resync)
{
	util.print_debug("resync:"+resync);
	var iblock = new Array(block_size);
	var ablock = new Array(block_size);
	var i, n = '';
	var text = [];

	// initialisation vector
	for(i=0; i < block_size; i++) iblock[i] = 0;

	iblock = blockcipherencryptfn(iblock, key);
	for(i = 0; i < block_size; i++)
	{
		ablock[i] = ciphertext.charCodeAt(i);
		iblock[i] ^= ablock[i];
	}

	ablock = blockcipherencryptfn(ablock, key);

	util.print_debug("openpgp_cfb_decrypt:\niblock:"+util.hexidump(iblock)+"\nablock:"+util.hexidump(ablock)+"\n");
	util.print_debug((ablock[0]^ciphertext.charCodeAt(block_size)).toString(16)+(ablock[1]^ciphertext.charCodeAt(block_size+1)).toString(16));
	
	// test check octets
	if(iblock[block_size-2]!=(ablock[0]^ciphertext.charCodeAt(block_size))
	|| iblock[block_size-1]!=(ablock[1]^ciphertext.charCodeAt(block_size+1)))
	{
		util.print_eror("error duding decryption. Symmectric encrypted data not valid.");
		return text.join('');
	}
	
	/*  RFC4880: Tag 18 and Resync:
	 *  [...] Unlike the Symmetrically Encrypted Data Packet, no
   	 *  special CFB resynchronization is done after encrypting this prefix
     *  data.  See "OpenPGP CFB Mode" below for more details.

	 */
	
	if (resync) {
	    for(i=0; i<block_size; i++) iblock[i] = ciphertext.charCodeAt(i+2);
		for(n=block_size+2; n<ciphertext.length; n+=block_size)
		{
			ablock = blockcipherencryptfn(iblock, key);

			for(i = 0; i<block_size && i+n < ciphertext.length; i++)
			{
				iblock[i] = ciphertext.charCodeAt(n+i);
				text.push(String.fromCharCode(ablock[i]^iblock[i])); 
			}
		}
	} else {
		for(i=0; i<block_size; i++) iblock[i] = ciphertext.charCodeAt(i);
		for(n=block_size; n<ciphertext.length; n+=block_size)
		{
			ablock = blockcipherencryptfn(iblock, key);
			for(i = 0; i<block_size && i+n < ciphertext.length; i++)
			{
				iblock[i] = ciphertext.charCodeAt(n+i);
				text.push(String.fromCharCode(ablock[i]^iblock[i])); 
			}
		}
		
	}
	
	return text.join('');
}

function openpgp_cfb_decrypt_large(blockcipherencryptfn, block_size, key, ciphertext, resync, partialPackageLength, progressCallback)
{	
	self.debug("DOING THE NEW DECRYPTION");
	self.firstPackage = true;
	self.debug("resync:"+resync);
	self.debug("Partial package length: " + partialPackageLength);
	self.debug("Block size: "+ block_size);
	var iblock = new Array(block_size);
	var ablock = new Array(block_size);
	var i, n = '';
	var text = [];
	var length = ciphertext.length;
	util.print_debug("Cipher length: "+ length);
	
	// initialisation vector
	for(i=0; i < block_size; i++) {iblock[i] = 0;}

	iblock = blockcipherencryptfn(iblock, key);
	for(i = 0; i < block_size; i++)
	{
		ablock[i] = ciphertext.get(i);
		iblock[i] ^= ablock[i];
	}
	ablock = blockcipherencryptfn(ablock, key);
	
	if(iblock[block_size-2]!=(ablock[0]^ciphertext.get(block_size))
	|| iblock[block_size-1]!=(ablock[1]^ciphertext.get(block_size+1)))
	{
		util.print_error("error during decryption. Symmectric encrypted data not valid.");
		return text.join('');
	}
	
	/*  RFC4880: Tag 18 and Resync:
	 *  [...] Unlike the Symmetrically Encrypted Data Packet, no
   	 *  special CFB resynchronization is done after encrypting this prefix
     *  data.  See "OpenPGP CFB Mode" below for more details.

	 */
	
	if (resync) {
		var outerIndex = 0;
		for(i=0; i<block_size; i++) iblock[i] = ciphertext.get(i+2);
		partialPackageLength = partialPackageLength - (block_size+2);
		util.print_debug("Partial package length: " + partialPackageLength);
	    
		var progressCounter = 0;
	    for(n=block_size+2; n<ciphertext.length; n+=block_size)
		{
			ablock = blockcipherencryptfn(iblock, key);

			for(i = 0; i<block_size && i+n < ciphertext.length; i++)
			{
				if(partialPackageLength > 0 && outerIndex == partialPackageLength) {
					var offset = 0;
					var tmplen;
					if (ciphertext.get(n+i) < 192) {
						tmplen = ciphertext.get(n+1);
						offset = 1;
						self.debug("new templen 0: " + tmplen);
					} else if (ciphertext.get(n+i) >= 192 && ciphertext.get(n+i) < 224) {
						tmplen = ((ciphertext.get(n+i) - 192) << 8)
								+ (ciphertext.get(n+i+1)) + 192;
						self.debug("new templen 192: " + tmplen);
						offset = 2;
					} else if (ciphertext.get(n+i) > 223
							&& ciphertext.get(n+i) < 255) {
						
						tmplen = (1 << (ciphertext.get(n+i) & 0x1F));
						self.debug("new templen 223: " + tmplen);
						offset = 1;
					} else {
						var tmp = n+i+1;
						
						tmplen = (ciphertext.get(tmp++) << 24)
								| (ciphertext.get(tmp++) << 16)
								| (ciphertext.get(tmp++) << 8)
								| ciphertext.get(tmp++);
						self.debug("new templen: " + tmplen);
						offset = 5;
					}
					n += offset;
					partialPackageLength += tmplen;
				}
				iblock[i] = ciphertext.get(n+i);
				text.push(String.fromCharCode(ablock[i]^iblock[i])); 
				outerIndex++;
			}
			
			if((progressCounter%4000) == 0 && progressCounter>0) {
				var percent = Math.round(((n/length) * 100)*Math.pow(10,2))/Math.pow(10,2);
				if(progressCallback != undefined) {
					progressCallback(percent);
				}
			}
			if((progressCounter%16000) == 0 && progressCounter>0) {
				self.saveDecryptedData(text);
				text = new Array();
			}
			progressCounter++;
		}
	} else {
		for(i=0; i<block_size; i++) iblock[i] = ciphertext.get(i).charCodeAt();
		for(n=block_size; n<ciphertext.length; n+=block_size)
		{
			ablock = blockcipherencryptfn(iblock, key);
			for(i = 0; i<block_size && i+n < ciphertext.length; i++)
			{
				iblock[i] = ciphertext.get(n+i).charCodeAt();
				text.push(String.fromCharCode(ablock[i]^iblock[i])); 
			}
		}
		
	}
	
	return text.join('');
}

function normal_cfb_encrypt(blockcipherencryptfn, block_size, key, plaintext, iv) {
	var blocki ="";
	var blockc = "";
	var pos = 0;
	var cyphertext = [];
	var tempBlock = [];
	blockc = iv.substring(0,block_size);
	while (plaintext.length > block_size*pos) {
		var encblock = blockcipherencryptfn(blockc, key);
		blocki = plaintext.substring((pos*block_size),(pos*block_size)+block_size);
		for (var i=0; i < blocki.length; i++)
		    tempBlock.push(String.fromCharCode(blocki.charCodeAt(i) ^ encblock[i]));
		blockc = tempBlock.join('');
		tempBlock = [];
		cyphertext.push(blockc);
		pos++;
	}
	return cyphertext.join('');
}

function normal_cfb_decrypt(blockcipherencryptfn, block_size, key, ciphertext, iv) { 
	var blockp ="";
	var pos = 0;
	var plaintext = [];
	var offset = 0;
	if (iv == null)
		for (var i = 0; i < block_size; i++) blockp += String.fromCharCode(0);
	else
		blockp = iv.substring(0,block_size);
	while (ciphertext.length > (block_size*pos)) {
		var decblock = blockcipherencryptfn(blockp, key);
		blockp = ciphertext.substring((pos*(block_size))+offset,(pos*(block_size))+(block_size)+offset);
		for (var i=0; i < blockp.length; i++) {
			plaintext.push(String.fromCharCode(blockp.charCodeAt(i) ^ decblock[i]));
		}
		pos++;
	}
	
	return plaintext.join('');
}
