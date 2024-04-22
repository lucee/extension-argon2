component extends="org.lucee.cfml.test.LuceeTestCase" labels="s3" {
	function run( testResults , testBox ) {
		describe( title="Test suite for Argon2CheckHash()", body=function() {
			it(title="check Argon2CheckHash", body = function( currentSpec ) {
				var hashedValue = GenerateArgon2Hash("CFDocs.org");
				expect(Argon2CheckHash( "CFDocs.org", hashedValue)).ToBeTrue();
			});		
		});
	}

}