component extends="org.lucee.cfml.test.LuceeTestCase" labels="argon2" {

	function run( testResults , testBox ) {
		describe( title="Test suite for Argon2CheckHash()", body=function() {
			it(title="check Argon2CheckHash (default)", body = function( currentSpec ) {
				var hashedValue = GenerateArgon2Hash("CFDocs.org");
				expect( hashedValue ).toInclude( "$argon2i$" );
				expect(Argon2CheckHash( "CFDocs.org", hashedValue)).ToBeTrue();
			});

			it(title="check Argon2CheckHash (argon2i)", body = function( currentSpec ) {
				var hashedValue = GenerateArgon2Hash("CFDocs.org", "argon2i");
				expect( hashedValue ).toInclude( "$argon2i$" );
				expect(Argon2CheckHash( "CFDocs.org", hashedValue)).ToBeTrue();
			});

			it(title="check Argon2CheckHash (argon2d)", body = function( currentSpec ) {
				var hashedValue = GenerateArgon2Hash("CFDocs.org", "argon2d");
				expect( hashedValue ).toInclude( "$argon2d$" );
				expect(Argon2CheckHash( "CFDocs.org", hashedValue)).ToBeTrue();
			});

			it(title="check Argon2CheckHash (argon2id)", body = function( currentSpec ) {
				var hashedValue = GenerateArgon2Hash("CFDocs.org", "argon2id");
				expect( hashedValue ).toInclude( "$argon2id$" );
				expect(Argon2CheckHash( "CFDocs.org", hashedValue)).ToBeTrue();
			});
		});
	}

}

