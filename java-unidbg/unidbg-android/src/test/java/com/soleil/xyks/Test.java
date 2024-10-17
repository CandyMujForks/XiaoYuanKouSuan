package com.soleil.xyks;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.CharArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import net.dongliu.apk.parser.bean.CertificateMeta;

import java.io.File;
import java.io.IOException;

public class Test extends AbstractJni implements IOResolver<AndroidFileIO> {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass encoderClass;
    private final String methodSign = "zcvsd1wr2t(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;";


    Test() {
        String processName = "com.fenbi.android.leo";
        emulator = AndroidEmulatorBuilder.for64Bit()
                //这个Factory速度快
                .addBackendFactory(new DynarmicFactory(true))
                //traceCode的时候需要开启这个, 不然报错
//            .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName(processName)
                .build();

        //模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        //设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));


        //创建虚拟机, 让unidbg做一些签名校验的操作
        String apkPath = "unidbg-android/src/test/resources/apks/xiaoyuan/xxx1.apk";
        vm = emulator.createDalvikVM(new File(apkPath));

        emulator.getSyscallHandler().addIOResolver(this);

        //继承AbstractJni的接口
        vm.setJni(this);
        //设置是否打印Jni调用细节
        vm.setVerbose(false);

        //在模拟器上注册一个Android虚拟模块, 它会在内存中模拟Android系统的相关功能
        new AndroidModule(emulator, vm).register(memory);
        //已经加载apk后, 可以直接这样加载, 如果加固了需要先dump并修复so, 再使用new File(xxx.so)加载
        DalvikModule dm = vm.loadLibrary("RequestEncoder", true);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
        encoderClass = vm.resolveClass("com.fenbi.android.leo.utils.e");
    }

    public String getSign(String path) {

            Object[] args = {
                    new StringObject(vm, path),
                    new StringObject(vm, "wdi4n2t8edr"),
                    DvmInteger.valueOf(vm, (int) (3))

                    /**
                     * TODO 登录???->sign->
                     * https://github.com/GalacticDevOps/XiaoYuanKouSuan/issues/1
                    */

            };
            DvmObject<?> result = encoderClass.callStaticJniMethodObject(emulator, methodSign, args);
            String string = result != null ? result.getValue().toString() : "";
            System.out.println("result: " + result);
            return string;
    }

    public void destroy() throws IOException {
        try {
            emulator.close();
        } catch (IOException e) {

        }
    }

    public static void main(String[] args) throws IOException {
        Test test = new Test();
        test.getSign("/leo-game-pk/android/math/pk/match/v2");
        test.destroy();
    }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String s, int i) {
        return null;
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "android/os/Build$VERSION->SDK_INT:I":
                return 23;
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/fenbi/android/leo/activity/HomeActivity->b()Landroid/app/Application;":
                return vm.resolveClass("android/app/Application").newObject(null);
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/app/Application->getBaseContext()Landroid/content/Context;": {
                return vm.resolveClass("android/content/Context").newObject(null);
            }
            case "android/content/pm/Signature->toChars()[C": {
                CertificateMeta certificateMeta = (CertificateMeta) dvmObject.getValue();
                byte[] bytes = certificateMeta.getData();
                char[] chars = new char[bytes.length];
                for (int i = 0; i < bytes.length; i++) {
                    chars[i] = (char) bytes[i];
                }
                return new CharArray(vm, chars);
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }
}
