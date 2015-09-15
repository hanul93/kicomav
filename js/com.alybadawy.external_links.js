// 
// This JS is for making external link sopen in new tab, and regular links should be defaulted to same tab.
                                             
$(document).ready(function() { 
	$("a[href^=http]").each(function(){ 
		if(this.href.indexOf(location.hostname) == -1) { 
			$(this).attr({ target: "_blank" });
		 } 
	})
});

