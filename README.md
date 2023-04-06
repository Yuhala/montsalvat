# Graal SGX Project
- `Project progress`: ![85%](https://progress-bar.dev/85)
- This branch represents a modification of graal vm CE to run full native images in Intel SGX enclaves.


## Project goals/milestones
- The [project's](docs/ero-proposal.pdf) main goal is to extend GraalVM native images with TEE (Intel SGX) functionality. We have the following milestones: 
- [x] Running a full native image java program inside the enclave for a start.
- [x] Produce 2 separate binaries with trusted/untrusted methods.
- [x] Generation of transition routines for ecalls/ocalls.
- [x] Creating proxy and mirror objects across both runtimes (primitive params only).
- [x] GC modifications to synchronize proxy/mirror object destructions (proxy cleaner class).
- [x] Object parameter and return types via serialization.
- [ ] Validating our approach with a motivating example e.g executing smart contracts.
- [ ] Adding PM functionality to our system. 

- [Meeting reports](docs/meetings/README.md)

## Substrate VM
- Substrate VM is the component which creates native images and is the core repo we are working on.
- SVM supports AoT compilation of Java apps into standalone executable images (i.e native images).
- Native image includes the necessary components like mem management and thread scheduling from substrate VM: deoptimizer, GC, thread scheduling etc

## Building and running a substrate VM native image in an Intel SGX enclave on Linux.  
- Clone this repo to a directory in local environment, which we will call `graal-sgx-root`. Unless stated otherwise, all `cd` commands assume `graal-sgx-root` as the top working directory.
```
mkdir graal-sgx-root && cd graal-sgx-root
git clone https://gitlab.com/Yuhala/graal-tee.git


```
- Enter your credentials if asked: gitlab username + password.

### SGX Installation
- We created a script to install SGX for Ubuntu based systems: `16.04`, `18.04`, and `20.04`. It was tested on both `18.04` and `20.04`
- Copy the `sgx-install.sh` script from `graal-tee` folder into `graal-sgx-root`: 
```
cp graal-tee/sgx-install.sh .

```
- The script by default will install SGX tools with debug information included. To install the tools without debug information, change the value of `debug_info` to `0`.
- Run the SGX install script:
```
./sgx-install.sh

```
- If your hardware does not support SGX, the necessary packages will still be installed; however you will have to use SGX in simulation mode in your makefiles (`SGX_MODE=SIM`).
- To use the SGX SDK custom debugger `sgx-gdb`, install these packages: `sudo apt libsgx-enclave-common-dbgsym libsgx-urts-dbgsym`.

### Installing graalvm tools
- Note: for `Ubuntu 20.04`,  you may need to properly configure an `http_proxy` to build graal properly. Our tests with `Ubuntu 18.04` worked without any issues.
- Install the [mx](https://github.com/graalvm/mx) build tool:

```
git clone https://github.com/graalvm/mx.git

```
- GraalVM's JIT compiler works with the default JVM as a plugin with the help of the JVM compiler interface (JVMCI), and thus requires a JDK which supports a graal-compatible version of JVMCI. You can find a compatible version in the `graal-tee` folder: `openjdk-8u282+08-jvmci-21.1-b01-linux-amd64.tar.gz`. Other compatible versions can be found here: [jvmci releases](https://github.com/graalvm/graal-jvmci-8/releases).

- Copy and extract this file in `graal-sgx-root`.

```
cp graal-tee/openjdk-8u282+08-jvmci-21.1-b01-linux-amd64.tar.gz . 
tar -xvf openjdk-8u282+08-jvmci-21.1-b01-linux-amd64.tar.gz
openjdk1.8.0_282-jvmci-21.1-b01

```
- Copy the native image agent shared library to the `jre/lib/amd64` folder of this jdk. The native image agent generates useful config files for native images at runtime.

```
cp graal-tee/libnative-image-agent.so openjdk1.8.0_282-jvmci-21.1-b01/jre/lib/amd64

```

- Add `mx` to path and point `JAVA-HOME` to the jdk with jvmci:
```
cp graal-tee/config-env .
source config-env

```

### Building an application which can be separated into trusted and untrusted portions.
- This tutorial will show you how to build a java application which can execute functionality in and out of an SGX enclave. 

- You begin by building your appication classes. In this sample application, we have 3 application classes: `Contract.java`, `Asset.java` and `Peer.java`, and the main class `Main.java`. These files should be all grouped into a folder which should be your application package. The latter should be added as a subfolder to `substratevm` and the `APP_PKG` variable in [build.sh](build.sh) should be modified with the name of your app package. The application package for our example is `smartc`. 

- We provide the annotation `SecurityInfo` to specify security properties of your application classes. Annotate trusted classes with `@SecurityInfo(security = "trusted")` and untrusted classes with `@SecurityInfo(security = "untrusted")`. Your application main class should always be an untrusted class. The reason being we create special GC threads in the main method: threads cannot be created from within SGX enclaves. 

- Once your application has been correctly annotated, you run the [build.sh](build.sh) script to build your app into an SGX application. During the build process, the application classes are transformed after compilation with `javac`. Two native images are built: a trusted image which will be linked to the trusted part of the SGX app and an untrusted image which will be linked to the untrusted part. For the trusted image build, `static relay methods` are added to each trusted class, for each class method, and all untrusted class methods are stripped and replaced with `ocall transitions`. During untrusted image building, the reverse happens. 

- As a result, every untrusted object created in the trusted runtime is simply a `proxy` for the real (`mirror`) copy/object in the untrusted runtime and vice versa. The mirror objects are stored in a registry together with the hash/id of the corresponding proxy in the opposite runtime. Thus each time a proxy calls an instance method a transition is done, the corresponding mirror object is located in the registry and the instance method is called on it. For static methods, the registry is not used; the corresponding method is simply called on the class. All this is done automatically by our bytecode transformer so the programmer need not worry about these technical details. All they need to do is annotate their classes accordingly or simply provide a list of trusted and untrusted classes.

- Methods of unannotated classes (`don't care classes`) will be compiled fully in any runtime if they are reachable there. For example JDK utility methods. As a result unannotated class objects will not have any proxy/mirror variants.

- Primitive and object types can be passed as parameters. However we still have issues with object return types. Don't-care objects are all serialized when passed across the enclave boundary and recreated at the other side.

- Many other interesting things are done under the hood by our system, but are out of the scope of this simple tutorial. The full internal workings of the system will be described in a corresponding paper.

- To build and test the sample application, CD into `graal-tee` directory and run the script: `build.sh` script. 

```bash
cd graal-tee
./build.sh 

```
- The above script also leverages the native image agent tool to generate useful configurations files in case your application uses reflection, serialization etc.

- The script builds two native images: `main_in.o` (trusted object) and `main_out.o` (untrusted object) which will be copied to the `sgx module` and linked to the trusted and untrusted runtimes respectively of the resulting Intel SGX application. The corresponding proxy routines and `EDL` files for SGX ecalls and ocalls are generated by the `SGX Proxy Generator`.

- CD into the `sgx module` and run the script `make clean && make` to build the final enclave application. 

```bash
cd graal-tee/sgx
make clean && make

```
- Run the resulting program `app`.

```bash
./app

```

## Possible build errors
- In the event of linker errors with `liblibchelper.a`, remove the latter from `sgx/Common` folder and replace it with the one built during the build process above which can be found here: `substratevm/mxbuild/linux-amd64/SVM_HOSTED_NATIVE/linux-amd64/liblibchelper.a`

- Rebuild the SGX program.

## Next Steps
- Integrating serialization for marshalling object types across the enclave boundary.
- Tests and benchmarking with real java projects.

## Other resources
- Article on Graal compiler by Chris Seaton: https://chrisseaton.com/truffleruby/jokerconf17/
- Medium article on native images by Christian Wimmer: https://medium.com/graalvm/isolates-and-compressed-references-more-flexible-and-efficient-memory-management-for-graalvm-a044cc50b67e