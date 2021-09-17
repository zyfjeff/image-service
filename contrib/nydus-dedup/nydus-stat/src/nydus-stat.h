// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#include <map>
#include <vector>
#include <string>

// Save the results of the image analysis of this program
class ImageStat
{
public:
    ImageStat(){};
    ImageStat(int totalChunk, int actualChunk, int duplicateChunk, int uniqueChunk);

    int totalChunk = -1;
    int actualChunk = -1;    // actualChunk === chunkHash.size();
    int duplicateChunk = -1; // duplicateChunk + uniqueChunk === actualChunk;
    int uniqueChunk = -1;
    double duplicateRate = -1; // duplicateRate === 1 - actualChunk / totalChunk;
};

// Save image metadata, This class must call init() after construction
class Image
{
public:
    Image(std::string name, std::string logPath);
    Image(std::string name, std::vector<std::string> imageLog);

    ImageStat getImageStat();
    std::string getName();
    std::map<std::string, int> getChunkHash();

    int Init();
    ImageStat InitImageStat();
    ImageStat AnalyzeSingleImage();
    double getImageSize(std::map<std::string, double> &globalChunkSize);

    static std::vector<std::string> InitImageLog(std::string logPath);

protected:
    std::string name;
    std::string logPath;
    std::vector<std::string> imageLog;
    std::map<std::string, int> chunkHash;
    ImageStat imageStat;

private:
    double size = -1.0;
};

// Save Nydus image metadata, This class must call init() after construction
class NydusImage : public Image
{
public:
    NydusImage(std::string name, std::string logPath) : Image(name, logPath){};
    NydusImage(std::string name, std::vector<std::string> imageLog) : Image(name, imageLog){};

    int Init();
    int PrintImageStats();

    static std::pair<std::vector<NydusImage>, std::map<std::string, int>> AnalyzeImages(std::vector<std::string> &fileList, std::map<std::string, double> &globalChunkSize);
    static std::map<std::string, int> GenerateBasicImage(std::map<std::string, int> &globalChunkHashs, int threshold);
    static std::vector<NydusImage> RebuildImage(std::map<std::string, int> &basicImage, std::vector<NydusImage> &sourceImages);
    static double CountImagesSize(std::vector<NydusImage> &sourceImages, std::map<std::string, double> &globalChunkSize);
    static std::map<std::string, double> InitChunkSizeMap(std::vector<std::string> &fileList);

private:
    static std::vector<NydusImage> InitImageList(std::vector<std::string> &fileList, int &totalChunkSum, int &actualChunkSum, std::map<std::string, int> &globalChunkHashs);
    static int ChunkFrequencyReport(std::map<std::string, int> &source, int globalChunkSum);
    static int ImageDuplicationReport(std::vector<NydusImage> &images);
};

// Save Ociv1 image metadata
class Ociv1Image : public Image
{
public:
    Ociv1Image(std::string name, std::string logPath) : Image(name, logPath){};

    static std::map<std::string, double> AnalyzeImages(std::vector<std::string> &fileList);
};

// Save the results of the basic image analysis of this program, This class must call init() after construction
class BasicImageStat
{
public:
    int Print();
    int Init(std::map<std::string, int> &basicImage, std::vector<NydusImage> &sourceImages, std::map<std::string, double> &globalChunkSize);

private:
    double oldSize;
    double basicSize;
    double excludeSize;
    double includeSize;
    double finalSize;
    double ratio;
};

// Save the regenerated base image metadata
class BasicImage
{
public:
    static int PrintRebuildReport(std::vector<BasicImageStat> &statsList);
    static int AnalyzeRebuildImages(std::vector<NydusImage> &sourceImages, std::map<std::string, int> &globalChunkHashs, std::map<std::string, double> &globalChunkSize);
    static int compareWithBasicImage(BasicImage &basicImage, NydusImage &sourceImage, std::map<std::string, double> &globalChunkSize);
    static int AnalyzeRebuildResult(BasicImage &basicImage, std::vector<NydusImage> &sourceImages, std::map<std::string, double> &globalChunkSize);

    double getImageSize(std::map<std::string, double> &globalChunkSize);

    std::map<std::string, int> getHashs();

private:
    std::map<std::string, int> chunkHash;
    std::string name;
    double size = -1.0;
    int threshold;
};