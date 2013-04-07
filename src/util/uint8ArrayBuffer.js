function uint8ArrayBuffer(blob) {
	this.blob = blob;
	this.startIndex = 0;
	this.stopIndex = 0;
	this.buff = [];
	this.reader = new FileReaderSync();
	this.length = blob.size;
	
	function getVirtualIndex(absoluteIndex) {
		return absoluteIndex - this.startIndex;
	}
	
	function readBytes(start, stop) {
		if(stop > this.length) {
			stop = this.length;
		}
		
		var tmpblob = this.slice(start, stop);
		var tmpData = this.reader.readAsArrayBuffer(tmpblob);
		this.buff = new Uint8Array(tmpData, 0);
		
		this.startIndex = start;
		this.stopIndex = stop;
	}
	
	function get(index, stopIndex) {
		if(stopIndex == undefined) {
			if(index >= this.startIndex && index < this.stopIndex) {
				return this.buff[index - this.startIndex];
			} else {
				this.readBytes(index, index+524288);
				virtualIndex = this.getVirtualIndex(index);
				if(index >= this.startIndex && index < this.stopIndex) {
					return this.buff[virtualIndex];
				} else {
					; // TODO: What to do here?
				}
			}
		} else {
			this.readBytes(index, stopIndex);
			return this.buff;
		}
	}
	
	// TODO: Bug when setting value in buff. Overwritten if someone asks for a smaller value than what's in the buff.
	// We need to write straight to the blob and reset the buffer.
	function set(index, value) {
		var prepend = this.slice(0, index);
		var append = this.slice(index, (this.length-1));
		self.debug(prepend.size + " " + append.size + " " + index + " " + this.length);
		var val = new Int32Array(1);
		val[0] = value;
		this.blob = new Blob([prepend, util.getArrayStoreFormat(val), append], {type: 'application/octet-stream'});
		this.startIndex = 0;
		this.stopIndex = 0;
		this.length = this.blob.size;
		self.debug("New length after set operation: " + this.blob.size + " " + this.length);
	}
	
	function slice(start, end) {
		if (blob.mozSlice) {
			return this.blob.mozSlice(start, end);
		} else if(blob.slice) {
			return this.blob.slice(start, end);
		} else if(blob.webkitSlice) {
			return this.blob.webkitSlice(start, end);
		}
	}
	
	function prepend(array) {
		self.debug(this.readAs);
		this.startIndex = 0;
		this.stopIndex = 0;
		this.blob = new Blob([util.getArrayStoreFormat(array), this.blob], {type: 'application/octet-stream'});
		//self.debug("Created a new blob with length: " + this.blob.size);
		
		this.length = this.blob.size;
	}
	
	function append(array) {
		this.startIndex = 0;
		this.stopIndex = 0;
		this.blob = new Blob([this.blob, util.getArrayStoreFormat(array)], {type: 'application/octet-stream'});

		this.length = this.blob.size;
		//self.debug("Created a new blob with length: " + this.length);
		
	}
	
	this.readBytes = readBytes;
	this.get = get;
	this.set = set;
	this.getVirtualIndex = getVirtualIndex;
	this.slice = slice;
	this.prepend = prepend;
	this.append = append;
	
}