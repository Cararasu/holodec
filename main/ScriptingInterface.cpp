#include "ScriptingInterface.h"

/*
extern "C" {
#include <Python.h>
}

namespace holodec {

	//needed for Scripting

	//state
	//	architecture
	//	binary
	//	function

	PyObject* setupContext (Architecture* arch, Binary* binary, Function* func, PyObject* dict = nullptr) {
		if (!dict) {
			dict = PyDict_New();
		} else {
			//TODO maybe decrease references of old Objects
		}
		if (arch)
			PyDict_SetItemString (dict, "arch", PyCapsule_New (arch, "holodec::Architecture", nullptr));
		if (binary)
			PyDict_SetItemString (dict, "binary", PyCapsule_New (binary, "holodec::Binary", nullptr));
		if (func)
			PyDict_SetItemString (dict, "func", PyCapsule_New (func, "holodec::Function", nullptr));
		return dict;
	}


	//setExpr...(arch, binary, func, exprId, value)

	extern "C" {
		PyObject * py_holodec_test (PyObject *self, PyObject *args) {
			PyObject* obj = PyTuple_GetItem (args, 0);
			PyObject* archObj = PyDict_GetItemString (obj, "arch");

			Architecture* arch = (Architecture*) PyCapsule_GetPointer (archObj, "holodec::Architecture");
			printf ("%d\n", arch);
			printf ("Test %s\n", arch->name.cstr());
			return PyUnicode_FromString (arch->name.cstr());
		}
		PyObject * py_arch_get_name (PyObject *self, PyObject *args) {
			if (PyTuple_Size (args) < 1)
				assert (false);
			PyObject* context = PyTuple_GetItem (args, 0);
			PyObject* archObj = PyDict_GetItemString (context, "arch");
			Architecture* arch = (Architecture*) PyCapsule_GetPointer (archObj, "holodec::Architecture");
			return PyUnicode_FromString (arch->name.cstr());
		}
		PyObject * py_arch_get_descr (PyObject *self, PyObject *args) {
			if (PyTuple_Size (args) < 1)
				assert (false);
			PyObject* context = PyTuple_GetItem (args, 0);
			PyObject* archObj = PyDict_GetItemString (context, "arch");
			Architecture* arch = (Architecture*) PyCapsule_GetPointer (archObj, "holodec::Architecture");
			return PyUnicode_FromString (arch->desc.cstr());
		}
		PyObject * py_arch_get_bitbase (PyObject *self, PyObject *args) {
			if (PyTuple_Size (args) < 1)
				assert (false);
			PyObject* context = PyTuple_GetItem (args, 0);
			PyObject* archObj = PyDict_GetItemString (context, "arch");
			Architecture* arch = (Architecture*) PyCapsule_GetPointer (archObj, "holodec::Architecture");
			return PyLong_FromUnsignedLongLong (arch->bitbase);
		}
		PyObject * py_arch_get_wordbase (PyObject *self, PyObject *args) {
			if (PyTuple_Size (args) < 1)
				assert (false);
			PyObject* context = PyTuple_GetItem (args, 0);
			PyObject* archObj = PyDict_GetItemString (context, "arch");
			Architecture* arch = (Architecture*) PyCapsule_GetPointer (archObj, "holodec::Architecture");
			return PyLong_FromUnsignedLongLong (arch->wordbase);
		}
		//holodec
		//holodec.arch
		//holodec.func
		//holodec.binary
		//holodec.ssa
		
		
		//helpers
		//.module(nullptr, "")
		//.function(nullptr, ptr, nullptr, ptr)
		//.enum("").value(nullptr, 1)
		//.value(nullptr, ...)
		
		//desc
		//bitbase
		//wordbase
		//registers
		//stacks
		//memories
		//ccs
		//instrdefs
		//
	}

	static PyMethodDef holodecMethods[] = {
		{
			"test", py_holodec_test, METH_VARARGS,
			"Return the number of arguments received by the process."
		},
		{ "getName", py_arch_get_name, METH_VARARGS, nullptr },
		{ "getDescr", py_arch_get_descr, METH_VARARGS, nullptr },
		{ "getBitbase", py_arch_get_bitbase, METH_VARARGS, nullptr },
		{ "getWordbase", py_arch_get_wordbase, METH_VARARGS, nullptr },
		{NULL, NULL, 0, NULL}
	};
	static PyModuleDef holodecModule = {
		PyModuleDef_HEAD_INIT, "holodec", "holodec-module",
		0, holodecMethods
	};

	PyMODINIT_FUNC PyInit_holodec() {
		PyObject* module = PyModule_Create (&holodecModule);
		PyObject* modDict = PyModule_GetDict (module);
		PyDict_SetItemString (modDict, "testKey", module);
		return module;
	}



	void ScriptingInterface::testModule (Architecture* arch) {
		Py_SetProgramName (L"Holodec"); // optional but recommended
		PyImport_AppendInittab ("holodec", PyInit_holodec);
		Py_Initialize();

		PyObject *main_module = PyImport_ImportModule ("__main__");
		PyObject *module = PyImport_ImportModule ("holodec");


		PyObject* context = setupContext (arch, nullptr, nullptr);
		PyModule_AddObject (main_module, "context", context);



		PyRun_SimpleString ("import holodec, binascii\n"
		                    "print(context)\n"
		                    "print(holodec.test(context))\n"
		                    "print(holodec.getName(context))\n"
		                    "print(holodec.getDescr(context))\n"
		                    "print(holodec.getBitbase(context))\n"
		                    "print(holodec.getWordbase(context))\n"
		                    "print(holodec.testKey)\n");

	}
}
*/