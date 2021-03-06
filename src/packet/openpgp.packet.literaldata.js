// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @class
 * @classdesc Implementation of the Literal Data Packet (Tag 11)
 * 
 * RFC4880 5.9: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 */
function openpgp_packet_literaldata() {
	this.tagType = 11;

	/**
	 * parsing function for a literal data packet (tag 11).
	 * 
	 * @param {string} input payload of a tag 11 packet
	 * @param {integer} position
	 *            position to start reading from the input string
	 * @param {integer} len
	 *            length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.packetLength = len;
		// - A one-octet field that describes how the data is formatted.

		this.format = input[position];
		this.filename = input.substr(position + 2, input
				.charCodeAt(position + 1));
		this.date = new Date(parseInt(input.substr(position + 2
				+ input.charCodeAt(position + 1), 4)) * 1000);
		this.data = input.substring(position + 6
				+ input.charCodeAt(position + 1));
		return this;
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {String} data the data to be inserted as body
	 * @return {String} string-representation of the packet
	 */
	function write_packet(data) {
		data = data.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
		this.filename = "msg.txt";
		this.date = new Date();
		this.format = 't';
		var result = openpgp_packet.write_packet_header(11, data.length + 6
				+ this.filename.length);
		result += this.format;
		result += String.fromCharCode(this.filename.length);
		result += this.filename;
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 24) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 16) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 8) & 0xFF);
		result += String
				.fromCharCode(Math.round(this.date.getTime() / 1000) & 0xFF);
		result += data;
		this.data = data;
		return result;
	}
	
	function write_packet_large(data, filename) {
		this.filename = filename;
		this.date = new Date();
		this.format = 'b';
		var result = openpgp_packet.write_packet_header(11, data.length + 6
				+ this.filename.length);
		result += this.format;
		result += String.fromCharCode(this.filename.length);
		result += this.filename;
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 24) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 16) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 8) & 0xFF);
		result += String
				.fromCharCode(Math.round(this.date.getTime() / 1000) & 0xFF);
		//result += data;
		this.data = data;
		var tempArray = new Uint8Array(result.length);
		for(var i = 0; i<result.length; i++)
		{
			tempArray[i] = result[i].charCodeAt();
		}
		
		self.debug("Literal data header length: " + result.length);
		var blob = new Blob([util.getArrayStoreFormat(tempArray), data.blob], {type: 'application/octet-stream'});
		//var blob = new Blob([result, data.blob], {type: 'application/octet-stream'});
		
		self.debug("Literal data length: " + blob.size);
		
		return blob;
	}

	/**
	 * generates debug output (pretty print)
	 * 
	 * @return {string} String which gives some information about the keymaterial
	 */
	function toString() {
		return '5.9.  Literal Data Packet (Tag 11)\n' + '    length: '
				+ this.packetLength + '\n' + '    format: ' + this.format
				+ '\n' + '    filename:' + this.filename + '\n'
				+ '    date:   ' + this.date + '\n' + '    data:  |'
				+ this.data + '|\n' + '    rdata: |' + this.real_data + '|\n';
	}

	this.read_packet = read_packet;
	this.toString = toString;
	this.write_packet = write_packet;
	this.write_packet_large = write_packet_large;
}
