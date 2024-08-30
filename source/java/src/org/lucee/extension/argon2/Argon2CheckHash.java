package org.lucee.extension.argon2;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.loader.util.Util;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

public class Argon2CheckHash extends BIF {
	private static final long serialVersionUID = 4730626229333277363L;

	@Override
	public Object invoke(PageContext pc, Object[] args) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		if (args.length != 2) {
			throw eng.getExceptionUtil().createFunctionException(pc, "Argon2CheckHash", 2, 2, args.length);
		}
		Cast caster = eng.getCastUtil();
		return call(pc, caster.toString(args[0]), caster.toString(args[1]));
	}

	public static boolean call(PageContext pc, String input, String hash) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Argon2Types type;
		String variant = getVariant(pc, hash);
		if (Util.isEmpty(variant, true))
			throw eng.getExceptionUtil().createFunctionException(pc, "GenerateArgon2Hash", 1, "variant", "The Variant should be ARGON2i, ARGON2id or ARGON2d", null);
		variant = variant.trim();
		switch (variant.toLowerCase()) {
		case "argon2i":
			type = Argon2Types.ARGON2i;
			break;
		case "argon2d":
			type = Argon2Types.ARGON2d;
			break;
		case "argon2id":
			type = Argon2Types.ARGON2id;
			break;
		
		default:
			throw eng.getExceptionUtil().createFunctionException(pc, "Argon2CheckHash", 1, "variant", 
				"The Variant should be ARGON2i, ARGON2id or ARGON2d, was [" + variant + "]", null);
		}
		Argon2 argon2 = Argon2Factory.create(type);
		char[] carrInput = input == null ? new char[0] : input.toCharArray();
		return argon2.verify(hash, carrInput);
	}

	private static String getVariant(PageContext pc, String hash) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		StringBuilder variant = new StringBuilder();
		for (int i = 0, n = hash.length(); i < n; i++) {
			char c = hash.charAt(i);
			if (i == 0 && c != '$') {
				throw eng.getExceptionUtil().createFunctionException(pc, "Argon2CheckHash", 1, "variant", "The format of hash string is wrong", null);
			}
			if (i > 0 && c == '$') {
				return variant.toString();
			}
			if (i > 0) {
				variant.append(c);
			}
		}
		throw eng.getExceptionUtil().createFunctionException(pc, "Argon2CheckHash", 1, "variant", "The format of hash string is wrong", null);
	}
}