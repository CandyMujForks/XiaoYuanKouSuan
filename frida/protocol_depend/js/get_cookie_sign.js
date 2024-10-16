Java.perform(function () {
    console.log("Combined script loaded successfully");
    try {
        // 尝试加载 Request.Builder 类
        var RequestBuilder = Java.use('okhttp3.Request$Builder');
        var Request = Java.use('okhttp3.Request');
        var HttpUrl = Java.use('okhttp3.HttpUrl');
        var e = Java.use("com.fenbi.android.leo.utils.e");

        // 拦截 Request.Builder 的 build 方法
        RequestBuilder.build.implementation = function () {
//            console.log("Intercepted Request.Builder.build");
            // 调用原始方法
            var request = this.build();
            // 检查请求 URL
            var url = request.url().toString();
//            console.log("Intercepted request to URL: " + url);

            // 针对特定的 URL 进行处理
            if (url.startsWith('https://xyks.yuanfudao.com/bh5/leo-web-oral-pk/pk.html?')) {
//                console.log("Intercepted specific URL: " + url);

                // 执行 `get_cookie.js` 中的逻辑
                var parsedUrl = HttpUrl.parse(url);
                if (parsedUrl) {
                    var yfdUFromUrl = parsedUrl.queryParameter('YFD_U');
                    var headers = request.headers();
                    var originalCookieFromHeader = '';
                    var userAgentFromHeader = '';
                    var str = "/leo-game-pk/android/math/pk/match/v2";
                    var str2 = "wdi4n2t8edr";
                    var intParam = parseInt(Java.use("qh.a").f().h() / 1000);  // 获取 int 参数
                    var result = e.zcvsd1wr2t(str, str2, intParam);

                    console.log("input: ", str, str2, intParam);
//                    send(result);
                    console.log("output", result);
                    for (var i = 0; i < headers.size(); i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        if (name.toLowerCase() === 'cookie') {
                            originalCookieFromHeader = value;
                        }
                        if (name.toLowerCase() === 'user-agent') {
                            userAgentFromHeader = value;
                        }
                    }
                    if (originalCookieFromHeader && userAgentFromHeader) {
                        send({
                            url: url,
                            yfdU: yfdUFromUrl,
                            originalCookie: originalCookieFromHeader,
                            userAgent: userAgentFromHeader,
                            result: result
                        });
                    }
                } else {
                    console.log("Failed to parse URL");
                }

            }
            return request;
        };

        console.log("Started intercepting Request.Builder.build for specific URL");

    } catch (err) {
        console.log("Request.Builder not found: " + err);
        console.log(err.stack);  // 打印详细错误堆栈
    }
});
