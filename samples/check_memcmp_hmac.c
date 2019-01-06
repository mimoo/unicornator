if(!memcmp(stored_hmac, hmac, HMAC_SHA512_SIZE))
	printk(KERN_INFO "HMACs match");
 else
	 printk(KERN_INFO "HMACs do not match"); 
