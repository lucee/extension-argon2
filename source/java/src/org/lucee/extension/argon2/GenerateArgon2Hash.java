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
import lucee.runtime.util.Decision;

public class GenerateArgon2Hash extends BIF {
	private static final long serialVersionUID = 61397352504711269L;

	@Override
	public Object invoke(PageContext pc, Object[] args) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		if (args.length < 1 || args.length > 5) {
			throw eng.getExceptionUtil().createFunctionException(pc, "GenerateArgon2Hash", 5, 5, args.length);
		}

		Decision dec = eng.getDecisionUtil();
		Cast cast = eng.getCastUtil();

		// input
		String input = cast.toString(args[0]);

		// variant
		Argon2Types variant = Argon2Types.ARGON2i;
		if (args.length > 1) {
			String tmp = dec.isEmpty(args[1]) ? null : cast.toString(args[1]);
			if (!Util.isEmpty(tmp, true)) {
				tmp = tmp.trim();
				switch (tmp.toLowerCase()) {
				case "argon2i":
					variant = Argon2Types.ARGON2i;
					break;
				case "argon2d":
					variant = Argon2Types.ARGON2d;
					break;
				default:
					throw eng.getExceptionUtil().createFunctionException(pc, "GenerateArgon2Hash", 1, "variant", "The Variant should be ARGON2i or ARGON2d", null);
				}
			}
			else variant = null;
		}

		// parallelismFactor
		int parallelismFactor = 1;
		if (args.length > 2) {
			parallelismFactor = cast.toIntValue(args[2]);
			if (parallelismFactor < 1 || parallelismFactor > 10) {
				throw eng.getExceptionUtil().createFunctionException(pc, "GenerateArgon2Hash", 2, "parallelismFactor", "The parallelism factor value should be between 1 and 10",
						null);
			}
		}

		// memoryCost
		int memory = 8;
		if (args.length > 3) {
			memory = cast.toIntValue(args[3]);
			if (memory < 8 || memory > 100000) {
				throw eng.getExceptionUtil().createFunctionException(pc, "GenerateArgon2Hash", 3, "memoryCost", "The memory cost value should be between 8 and 100000", null);
			}
		}

		// iterations
		int iterations = 8;
		if (args.length > 4) {
			iterations = cast.toIntValue(args[4]);
			if (iterations < 1 || iterations > 20) {
				throw eng.getExceptionUtil().createFunctionException(pc, "GenerateArgon2Hash", 4, "iterations", "The iterations value should be between 1 and 20", null);
			}
		}

		Argon2 argon2 = Argon2Factory.create(variant);

		char[] carrInput = input == null ? new char[0] : input.toCharArray();
		String hash = argon2.hash(iterations, memory, parallelismFactor, carrInput);
		boolean success = argon2.verify(hash, carrInput);

		if (!success) {
			throw eng.getExceptionUtil().createExpressionException("Hashing failed!");
		}
		return hash;
	}
}
