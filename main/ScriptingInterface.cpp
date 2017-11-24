#include "ScriptingInterface.h"

#include <Python.h>

namespace holodec{
	
	//needed for Scripting
	
	//state
	//	architecture
	//	binary
	//	function
	
	struct ScriptState{
		
	};
	
	
	//setExpr...(arch, binary, func, exprId, value)
	
	PyObject * holodec_test (PyObject *self, PyObject *args) {
		PyObject* obj = PyTuple_GetItem(args, 0);
		
		Architecture* arch = (Architecture*) PyCapsule_GetPointer(obj, "holodec.Architecture");
		printf("%d\n",arch);
		printf ("Test %s\n", arch->name.cstr());
		return Py_None;
	}

	static PyMethodDef holodecMethods[] = {
		{
			"test", holodec_test, METH_VARARGS,
			"Return the number of arguments received by the process."
		},
		{NULL, NULL, 0, NULL}
	};
	static PyModuleDef holodecModule = {
		PyModuleDef_HEAD_INIT, "holodec", "holodec-module",
		0, holodecMethods
	};
	
	PyMODINIT_FUNC PyInit_holodec(){
		return PyModule_Create (&holodecModule);
	}
	
	void ScriptingInterface::testModule(Architecture* arch) {
		Py_SetProgramName (L"Holodec"); /* optional but recommended */
		PyImport_AppendInittab("holodec", PyInit_holodec);
		Py_Initialize();
		
		PyObject *main_module = PyImport_ImportModule("__main__");
		
		PyObject* obj = PyCapsule_New(arch, "holodec.Architecture", nullptr);
		PyModule_AddObject(main_module, "a", obj);
		
		
		PyRun_SimpleString ("import holodec, binascii\n"
							"print(holodec.test(a))\n"
							"print(a)\n");
							
	}
}