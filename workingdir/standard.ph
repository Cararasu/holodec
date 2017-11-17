


matcher{
	rules{//required
		type(name=...,op=op,flag=...,size=...)
		argtype(name=...)
		argtype(name=...)
	}
	submatches{//optional
		match(index=1){
			matcher{...}
		}
	}
	actions{//optional - is executed if no submatch was found
		action ... 
	}
}