#include <opencv2/opencv.hpp>
#include <iostream>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <direct.h>
#include <io.h>

using namespace std;
using namespace cv;

struct Match {
    cv::Rect rect;
    double score;
    int num;
};

Mat Screenshoot;

std::vector<cv::Mat> templates;
std::vector<std::vector<cv::KeyPoint>> templateKeypoints;
std::vector<cv::Mat> templateDescriptors;

void loadTemplates() {
    cv::Ptr<cv::FeatureDetector> detector = cv::ORB::create();
    cv::Ptr<cv::DescriptorExtractor> extractor = cv::ORB::create();

    for (int num = 0; num <= 9; ++num) {
        cv::Mat templateImage = cv::imread(std::string("./src/") + std::to_string(num) + ".png");
        if (templateImage.empty()) {
            std::cerr << "Can not load template: " << num << std::endl;
            continue;
        }
        cv::Mat grayTemplate;
        cv::cvtColor(templateImage, grayTemplate, cv::COLOR_BGR2GRAY);
        cv::threshold(grayTemplate, grayTemplate, 127, 255, cv::THRESH_BINARY);

        std::vector<cv::KeyPoint> keypoints;
        cv::Mat descriptors;
        detector->detect(grayTemplate, keypoints);
        extractor->compute(grayTemplate, keypoints, descriptors);

        templates.push_back(grayTemplate);
        templateKeypoints.push_back(keypoints);
        templateDescriptors.push_back(descriptors);
    }
    std::cout << "Templates loaded successfully." << std::endl;
}

void refreshSrcImage(const std::string& Path) {
    // 执行截图命令并直接读取数据
    std::cout << "Capturing screenshot..." << std::endl;
    FILE* pipe = _popen("adb -s 127.0.0.1:16384 shell screencap -p", "rb");
    if (!pipe) {
        std::cerr << "Failed to capture screenshot." << std::endl;
        return;
    }

    std::vector<uint8_t> buffer(1024);
    std::vector<uint8_t> imageData;
    while (!feof(pipe)) {
        size_t bytesRead = fread(&buffer[0], 1, buffer.size(), pipe);
        imageData.insert(imageData.end(), buffer.begin(), buffer.begin() + bytesRead);
    }
    _pclose(pipe);

    // 将数据转换为 Mat
    cv::Mat image = cv::imdecode(imageData, cv::IMREAD_COLOR);
    if (image.empty()) {
        std::cerr << "Failed to decode screenshot." << std::endl;
        return;
    }

    std::cout << "Screenshot captured successfully." << std::endl;
    resize(image, Screenshoot, Size(400, 700)); // 减少图像尺寸
}

std::vector<Match> detect_digits(cv::Mat targetImage) {
    // 初始化 ORB 特征检测器和描述符匹配器
    cv::Ptr<cv::FeatureDetector> detector = cv::ORB::create();
    cv::Ptr<cv::DescriptorExtractor> extractor = cv::ORB::create();
    cv::Ptr<cv::DescriptorMatcher> matcher = cv::BFMatcher::create(cv::NORM_HAMMING);

    // 转换目标图像为灰度图像并二值化
    cv::Mat grayTarget;
    cv::cvtColor(targetImage, grayTarget, cv::COLOR_BGR2GRAY);
    cv::threshold(grayTarget, grayTarget, 127, 255, cv::THRESH_BINARY);

    // 存储所有匹配结果
    std::vector<Match> matches;

    // 使用并行处理
    class TemplateMatcher : public cv::ParallelLoopBody {
    public:
        TemplateMatcher(const cv::Mat& grayTarget, const std::vector<cv::Mat>& templates,
            const std::vector<std::vector<cv::KeyPoint>>& templateKeypoints,
            const std::vector<cv::Mat>& templateDescriptors,
            std::vector<Match>& matches,
            cv::Ptr<cv::FeatureDetector> detector,
            cv::Ptr<cv::DescriptorExtractor> extractor,
            cv::Ptr<cv::DescriptorMatcher> matcher)
            : grayTarget_(grayTarget), templates_(templates), templateKeypoints_(templateKeypoints),
            templateDescriptors_(templateDescriptors), matches_(matches),
            detector_(detector), extractor_(extractor), matcher_(matcher) {}

        void operator()(const cv::Range& range) const override {
            for (int num = range.start; num < range.end; ++num) {
                cv::Mat grayTemplate = templates_[num];
                std::vector<cv::KeyPoint> keypoints;
                cv::Mat descriptors;
                detector_->detect(grayTarget_, keypoints);
                extractor_->compute(grayTarget_, keypoints, descriptors);

                std::vector<cv::DMatch> good_matches;
                std::vector<cv::DMatch> matches1;
                matcher_->match(descriptors, templateDescriptors_[num], matches1);

                double min_dist = 100;
                double max_dist = 0;

                for (int i = 0; i < matches1.size(); i++) {
                    double dist = matches1[i].distance;
                    if (dist < min_dist) min_dist = dist;
                    if (dist > max_dist) max_dist = dist;
                }

                for (int i = 0; i < matches1.size(); i++) {
                    if (matches1[i].distance <= max(2 * min_dist, 30.0)) {
                        good_matches.push_back(matches1[i]);
                    }
                }

                if (good_matches.size() > 4) { // 至少有 4 个好的匹配点
                    std::vector<cv::Point2f> obj;
                    std::vector<cv::Point2f> scene;

                    for (size_t i = 0; i < good_matches.size(); i++) {
                        obj.push_back(templateKeypoints_[num][good_matches[i].trainIdx].pt);
                        scene.push_back(keypoints[good_matches[i].queryIdx].pt);
                    }

                    cv::Mat H = cv::findHomography(obj, scene, cv::RANSAC);

                    std::vector<cv::Point2f> obj_corners(4);
                    obj_corners[0] = cv::Point2f(0, 0);
                    obj_corners[1] = cv::Point2f(grayTemplate.cols, 0);
                    obj_corners[2] = cv::Point2f(grayTemplate.cols, grayTemplate.rows);
                    obj_corners[3] = cv::Point2f(0, grayTemplate.rows);

                    std::vector<cv::Point2f> scene_corners(4);
                    perspectiveTransform(obj_corners, scene_corners, H);

                    cv::Rect matchRect = cv::boundingRect(scene_corners);
                    matches_.push_back({ matchRect, 1.0, num });
                }
            }
        }

    private:
        const cv::Mat& grayTarget_;
        const std::vector<cv::Mat>& templates_;
        const std::vector<std::vector<cv::KeyPoint>>& templateKeypoints_;
        const std::vector<cv::Mat>& templateDescriptors_;
        std::vector<Match>& matches_;
        cv::Ptr<cv::FeatureDetector> detector_;
        cv::Ptr<cv::DescriptorExtractor> extractor_;
        cv::Ptr<cv::DescriptorMatcher> matcher_;
    };

    TemplateMatcher matcher(grayTarget, templates, templateKeypoints, templateDescriptors, matches, detector, extractor, matcher);
    cv::parallel_for_(cv::Range(0, templates.size()), matcher);

    // 对匹配结果进行非极大值抑制
    std::vector<Match> finalMatches;
    std::vector<bool> suppressed(matches.size(), false);

    for (size_t i = 0; i < matches.size(); ++i) {
        if (suppressed[i]) continue;
        finalMatches.push_back(matches[i]);

        for (size_t j = i + 1; j < matches.size(); ++j) {
            if (suppressed[j]) continue;

            double intersectionArea = (matches[i].rect & matches[j].rect).area();
            double unionArea = matches[i].rect.area() + matches[j].rect.area() - intersectionArea;
            double iou = intersectionArea / unionArea;

            if (iou > 0.5) {
                suppressed[j] = true;
            }
        }
    }

    // 按照横向坐标（x 坐标）排序
    std::sort(finalMatches.begin(), finalMatches.end(), [](const Match& a, const Match& b) {
        return a.rect.x < b.rect.x;
        });

    // 绘制结果并输出
    for (const auto& match : finalMatches) {
        cv::rectangle(targetImage, match.rect, cv::Scalar(0, 255, 0), 2);
        std::string label = "Digit " + std::to_string(match.num);
        cv::putText(targetImage, label, match.rect.tl(), cv::FONT_HERSHEY_SIMPLEX, 0.6, cv::Scalar(0, 255, 0), 2);
        std::cout << "Number: " << match.num << " Position: (" << match.rect.x << ", " << match.rect.y << ")\n";
    }

    cv::imshow("Detected Numbers Sorted", targetImage);

    return finalMatches;
}

int merge_vector(const std::vector<int>& v) {
    int num = 0;
    for (int i = 0; i < v.size(); i++) {
        num += v[i] * pow(10, v.size() - 1 - i);
    }
    return num;
}

int compare_match(const std::vector<Match>& result) {
    static int pre_num1 = 0;
    static int pre_num2 = 0;
    int repeat_flag = 0;

    std::vector<int> num1, num2;
    for (const auto& match : result) {
        if (match.rect.x < 150) // 根据实际情况调整
            num1.push_back(match.num);
        else
            num2.push_back(match.num);
    }
    int result1 = merge_vector(num1);
    int result2 = merge_vector(num2);

    std::cout << "Number merge1: " << result1 << std::endl;
    std::cout << "Number merge2: " << result2 << std::endl;

    if (result1 == pre_num1 && result2 == pre_num2)
        repeat_flag = 1;

    pre_num1 = result1;
    pre_num2 = result2;

    if (repeat_flag == 1) {
        repeat_flag = 0;
        return 0;
    }

    if (result1 > result2)
        return 1;
    else if (result1 < result2)
        return -1;
    else
        return 0;
}

std::string GetProgramDir() {
    wchar_t exeFullPath[MAX_PATH]; // Full path 
    std::string strPath = "";

    GetModuleFileName(NULL, exeFullPath, MAX_PATH);
    char CharString[MAX_PATH];
    size_t convertedChars = 0;
    wcstombs_s(&convertedChars, CharString, MAX_PATH, exeFullPath, _TRUNCATE);

    strPath = (std::string)CharString;    // Get full path of the file 

    int pos = strPath.find_last_of('\\', strPath.length());
    return strPath.substr(0, pos);  // Return the directory without the file name 
}

int process() {
    if (Screenshoot.empty()) {
        std::cerr << "Screenshoot is empty. Cannot proceed with processing." << std::endl;
        return -1;
    }

    cv::Mat srcImage = Screenshoot;

    cv::Rect roiRect(100, 180, 200, 100); // 根据实际情况调整

    // 检查 ROI 是否超出图像边界
    if (roiRect.x >= srcImage.cols || roiRect.y >= srcImage.rows ||
        roiRect.x + roiRect.width > srcImage.cols || roiRect.y + roiRect.height > srcImage.rows) {
        std::cerr << "ROI Flow Out！" << std::endl;
        return -1;
    }

    // 在原图上绘制 ROI 矩形
    cv::rectangle(srcImage, roiRect, cv::Scalar(0, 255, 0), 2);
    cv::Mat roiImage = srcImage(roiRect);

    // 显示结果图像
    //cv::imshow("ScreenShot", srcImage);

    std::vector<Match> result = detect_digits(roiImage);

    int cmp = compare_match(result);

    std::cout << "Result: " << cmp << std::endl;

    return cmp;
}

void action_bigger() {
    char buffer[100];
    sprintf_s(buffer, "adb -s 127.0.0.1:16384 shell input swipe %d %d %d %d 1", 664, 773, 802, 844);
    int ret = system(buffer);
    if (ret != 0) {
        std::cerr << "Failed to execute ADB command: " << buffer << std::endl;
    }
    else {
        std::cout << "ADB command executed successfully: " << buffer << std::endl;
    }
    sprintf_s(buffer, "adb -s 127.0.0.1:16384 shell input swipe %d %d %d %d 1", 802, 844, 696, 942);
    ret = system(buffer);
    if (ret != 0) {
        std::cerr << "Failed to execute ADB command: " << buffer << std::endl;
    }
    else {
        std::cout << "ADB command executed successfully: " << buffer << std::endl;
    }

    std::cout << "Execute action: Write bigger." << std::endl;
}

void action_smaller() {
    char buffer[100];
    sprintf_s(buffer, "adb -s 127.0.0.1:16384 shell input swipe %d %d %d %d 1", 805, 768, 652, 835);
    int ret = system(buffer);
    if (ret != 0) {
        std::cerr << "Failed to execute ADB command: " << buffer << std::endl;
    }
    else {
        std::cout << "ADB command executed successfully: " << buffer << std::endl;
    }
    sprintf_s(buffer, "adb -s 127.0.0.1:16384 shell input swipe %d %d %d %d 1", 652, 835, 781, 938);
    ret = system(buffer);
    if (ret != 0) {
        std::cerr << "Failed to execute ADB command: " << buffer << std::endl;
    }
    else {
        std::cout << "ADB command executed successfully: " << buffer << std::endl;
    }

    std::cout << "Execute action: Write smaller." << std::endl;
}

void action(int cmp) {
    if (cmp == 1)
        action_bigger();
    else if (cmp == -1)
        action_smaller();
}

int main() {
    string Path = GetProgramDir();
    system("adb connect 127.0.0.1:16384");

    loadTemplates();

    while (true) {
        refreshSrcImage(Path);

        if (Screenshoot.empty()) {
            std::cerr << "Failed to refresh screenshot." << std::endl;
            continue;
        }

        int cmp = process();

        if (cmp != 0) {
            action(cmp);
        }

        char c = waitKey(1);
        if (c == 27) {
            break;
        }
    }

    return 0;
}