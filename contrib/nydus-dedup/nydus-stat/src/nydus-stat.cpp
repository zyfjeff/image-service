// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <dirent.h>
#include <cassert>
#include <string>
#include <algorithm>
#include <iomanip>

#include <nlohmann/json.hpp>
#include "nydus-stat.h"

using namespace std;
using json = nlohmann::json;

// Comparator function to sort pairs according to second value
bool cmp(const pair<string, int> &a, const pair<string, int> &b)
{
    return a.second > b.second;
}

// Function to sort the map according to value in a (key-value) pairs
vector<pair<string, int>> SortMapByValue(const map<string, int> &source)
{

    // Declare vector of pairs
    vector<pair<string, int>> target;

    // Copy key-value pair from Map to vector of pairs
    for (auto &it : source)
    {
        target.push_back(it);
    }

    // Sort using comparator function
    sort(target.begin(), target.end(), cmp);

    return target;
}

// Count chunk frequency in chunk map
map<int, int> CountMap(const map<string, int> &source)
{
    map<int, int> result;
    for (auto &it : source)
    {
        if (result.find(it.second) == result.end())
        {
            result[it.second] = 1;
        }
        else
        {
            result[it.second]++;
        };
    }

    return result;
}

// Get the actual size of the image
double GetImageRealSizeByHash(const map<string, int> &imageChunks, const map<string, double> &globalChunkSize)
{
    double sizeSum = 0;
    for (const auto &kv : imageChunks)
    {
        if (globalChunkSize.find(kv.first) != globalChunkSize.end())
        {
            // Multiple chunks do not need to be saved repeatedly
            sizeSum = sizeSum + globalChunkSize.at(kv.first); //* kv.second;
        }
    }
    return sizeSum;
}

ImageStat::ImageStat(int totalChunk, int actualChunk, int duplicateChunk, int uniqueChunk)
{
    this->totalChunk = totalChunk;
    this->actualChunk = actualChunk;
    this->duplicateChunk = duplicateChunk;
    this->uniqueChunk = uniqueChunk;
    this->duplicateRate = 1 - (double)actualChunk / totalChunk;
}

string Image::getName()
{
    return name;
}

ImageStat Image::getImageStat()
{
    return imageStat;
}

map<string, int> Image::getChunkHash()
{
    return chunkHash;
}

Image::Image(string name, string logPath)
{
    this->name = name;
    this->logPath = logPath;
}

Image::Image(string name, vector<string> imageLog)
{
    this->name = name;
    this->imageLog = imageLog;
}

// Read image metadata from file
vector<string> Image::InitImageLog(string logPath)
{
    vector<string> imageLog;

    ifstream logStream;
    logStream.open(logPath, ios::in);
    if (!logStream.is_open())
    {
        perror("Error");
        throw std::runtime_error("FileError");
    }

    string hash;
    while (getline(logStream, hash))
    {
        imageLog.push_back(hash);
    }

    logStream.close();

    return imageLog;
}

// Get the statistical results of the image
ImageStat Image::InitImageStat()
{
    int totalChunk = 0;
    for (int i = 0; i < imageLog.size(); i++)
    {
        string hash = imageLog[i];
        if (chunkHash.find(hash) == chunkHash.end())
        {
            chunkHash[hash] = 1;
        }
        else
        {
            chunkHash[hash]++;
        };
        totalChunk++;
    }

    int uniqueChunk = 0;
    int duplicateChunk = 0;
    for (auto iter = chunkHash.begin(); iter != chunkHash.end(); iter++)
    {
        if (iter->second == 1)
        {
            uniqueChunk++;
        }
        else
        {
            duplicateChunk++;
        }
    }
    int actualChunk = chunkHash.size();

    assert(uniqueChunk + duplicateChunk == actualChunk);
    ImageStat stats(totalChunk, actualChunk, duplicateChunk, uniqueChunk);

    return stats;
}

// Analyze a single image
ImageStat Image::AnalyzeSingleImage()
{
    vector<string> imageLog = InitImageLog(name);
    ImageStat imageChunkStats = InitImageStat();

    // cout << "File: " << fileName << " Result" << endl;
    // cout << "Chunk count: " << imageChunkStats.totalChunk << endl;
    // cout << "Deduplicated chunk count: " << imageChunkStats.actualChunk << endl;
    // cout << "Duplication rate: " << imageChunkStats.duplicateRate * 100 << "%" << endl;
    // cout << endl;

    return imageChunkStats;
}

// Initialization class
int Image::Init()
{
    if (name.empty() || logPath.empty())
    {
        return -1;
    }

    imageLog = InitImageLog(logPath);
    imageStat = InitImageStat();

    return 0;
}

// Getter with cache to save calculation cost
double Image::getImageSize(map<string, double> &globalChunkSize)
{
    double result = 0.0;
    if (size < 0)
    {
        result = GetImageRealSizeByHash(chunkHash, globalChunkSize);
        size = result;
    }
    return size;
}

// Count and analyze the frequency of chunk appearance
int NydusImage::ChunkFrequencyReport(map<string, int> &source, int globalChunkSum)
{
    vector<pair<string, int>> target = SortMapByValue(source);

    map<int, int> stat = CountMap(source);

    int localSum = 0;

    cout << "-----------------------------------------------------------" << endl;
    cout << "Table 2: Chunk Frequency Report:" << endl;
    cout << "(A)Chunks\t(B)Count\t(C)Ratio\t(D)Overall" << endl;
    for (auto &it : stat)
    {
        int product = it.second * it.first;
        localSum = localSum + product;
        double percentage = (double)product / globalChunkSum;
        double percentageSum = (double)localSum / globalChunkSum;
        cout << it.second << "\t" << it.first << "\t" << percentage * 100 << "%\t" << percentageSum * 100 << "%" << endl;
    }
    cout << "(SUM) Number of Chunks actually stored: " << globalChunkSum << endl;
    cout << endl;
    cout << "Table 2 formula:" << endl;
    cout << "C = A * B / SUM" << endl;
    cout << "D = Σ C" << endl;
    cout << "-----------------------------------------------------------" << endl;
    cout << endl;

    return 0;
}

// Read Nydus image metadata from the file to initialize the image list
vector<NydusImage> NydusImage::InitImageList(vector<string> &fileList, int &totalChunkSum, int &actualChunkSum, map<string, int> &globalChunkHash)
{
    int fileCount = fileList.size();
    vector<NydusImage> images;

    for (int i = 0; i < fileCount; i++)
    {
        string filePath = fileList[i];
        NydusImage image("image" + to_string(i + 1), filePath);
        image.Init();
        images.push_back(image);

        totalChunkSum += image.imageStat.totalChunk;
        actualChunkSum += image.imageStat.actualChunk;

        for (const auto &kv : images[i].chunkHash)
        {
            globalChunkHash[kv.first] += 1;
        }
    }
    return images;
}

// Print the 1st report
int NydusImage::ImageDuplicationReport(vector<NydusImage> &images)
{
    cout << "-----------------------------------------------------------" << endl;
    cout << "Table 1: Image Duplication Report:" << endl;
    cout << "Image\t(A)Total\t(B)Actual\t(C)Ratio" << endl;
    for (int i = 0; i < images.size(); i++)
    {
        images[i].PrintImageStats();
    }
    return 0;
}

// Print the statistical results of the image
int NydusImage::PrintImageStats()
{
    cout << name << "\t" << imageStat.totalChunk << "\t" << imageStat.actualChunk << "\t" << imageStat.duplicateRate * 100 << "%" << endl;
    return 0;
}

// Initialization class
int NydusImage::Init()
{
    if (name.empty())
    {
        return -1;
    }

    if (logPath.empty() == false)
    {
        imageLog = InitImageLog(logPath);
    }

    imageStat = InitImageStat();

    // cout << "File: " << logPath << " Result" << endl;
    // cout << "Chunk count: " << imageStat.totalChunk << endl;
    // cout << "Deduplicated chunk count: " << imageStat.actualChunk << endl;
    // cout << "Duplication rate: " << imageStat.duplicateRate * 100 << "%" << endl;
    // cout << endl;

    return 0;
}

// Read Nydus image metadata from the file to initialize the hash table
map<string, double> NydusImage::InitChunkSizeMap(vector<string> &fileList)
{
    int fileCount = fileList.size();
    map<string, double> globalChunkSize;

    for (int i = 0; i < fileCount; i++)
    {
        string filePath = fileList[i];
        vector<string> imageLog = InitImageLog(filePath);

        string hash;
        double size;
        stringstream ss;
        for (int j = 0; j < imageLog.size(); j++)
        {
            ss.clear();
            ss << imageLog[j];
            ss >> hash >> size;
            globalChunkSize[hash] = size / 1024 / 1024;
        }
        ss.str("");
    }
    return globalChunkSize;
}

// Analyze the Nydus image list
// TODO: Maybe need to refactor to reduce coupling
pair<vector<NydusImage>, map<string, int>> NydusImage::AnalyzeImages(vector<string> &fileList, map<string, double> &globalChunkSize)
{
    int totalChunkSum = 0;
    int actualChunkSum = 0;
    map<string, int> globalChunkHash;
    vector<NydusImage> images = InitImageList(fileList, totalChunkSum, actualChunkSum, globalChunkHash);

    // print result table 2
    ChunkFrequencyReport(globalChunkHash, actualChunkSum);

    // print result table 1
    ImageDuplicationReport(images);

    int globallyUniqueChunkSum = globalChunkHash.size();
    double rate1 = 1 - (double)actualChunkSum / totalChunkSum;
    double rate2 = 1 - (double)globallyUniqueChunkSum / totalChunkSum;
    double rate3 = 1 - (double)globallyUniqueChunkSum / actualChunkSum;

    cout << "Group-1"
         << "\t" << totalChunkSum << "\t" << actualChunkSum << "\t" << rate1 * 100 << "%" << endl;
    cout << "Group-2"
         << "\t" << totalChunkSum << "\t" << globallyUniqueChunkSum << "\t" << rate2 * 100 << "%" << endl;
    cout << "Group-3"
         << "\t" << actualChunkSum << "\t" << globallyUniqueChunkSum << "\t" << rate3 * 100 << "%" << endl;
    cout << endl;
    cout << "Table 1 formula:" << endl;
    cout << "C = 1 - B / A" << endl;
    cout << "Group-1: Not optimized vs Nydus" << endl;
    cout << "Group-2: Not optimized vs Nydus + Global deduplication" << endl;
    cout << "Group-3: Nydus vs Nydus + Global deduplication" << endl;
    cout << "-----------------------------------------------------------" << endl;
    cout << endl;

    // print summary statistics
    cout << "-----------------------------------------------------------" << endl;
    cout << "Summary: " << endl;
    cout << "[Nydus]" << endl;
    cout << "Chunk Count: " << totalChunkSum << endl;
    cout << "The number of chunks actually stored in each Nydus mirror: " << actualChunkSum << endl;
    cout << "The number of Chunks that need to be stored globally: " << globallyUniqueChunkSum << endl;
    cout << "Theoretical maximum deduplication rate: " << rate3 * 100 << "%" << endl;
    cout << endl;
    return make_pair(images, globalChunkHash);
}

// Generate a basic image based on the threshold
map<string, int> NydusImage::GenerateBasicImage(map<string, int> &globalChunkHash, int threshold)
{
    map<string, int> basicImageHashs;

    for (const auto &kv : globalChunkHash)
    {
        if (kv.second >= threshold)
        {
            basicImageHashs[kv.first] = 1;
        }
    }

    return basicImageHashs;
}

// Generate a set of business images that do not contain reference chunks based on the basic image
vector<NydusImage> NydusImage::RebuildImage(map<string, int> &basicImage, vector<NydusImage> &sourceImages)
{
    vector<NydusImage> newImages;

    int imageNumber = 1;
    //Traverse all the images that need to be rebuilt
    for (const auto &sourceImage : sourceImages)
    {
        vector<string> imageLog;
        string imageName = "NewImage" + to_string(imageNumber);

        //Repackage chunks in the source image that do not exist in the base image
        map<string, int> currentImageHashs = sourceImage.chunkHash;
        for (const auto &chunk : currentImageHashs)
        {
            if (basicImage.find(chunk.first) == basicImage.end())
            {
                imageLog.push_back(chunk.first);
            }
        }
        NydusImage tempImage = NydusImage(imageName, imageLog);
        if (tempImage.Init() != 0)
        {
            throw std::runtime_error("Can not init image");
        }

        newImages.push_back(tempImage);
    }

    imageNumber++;
    return newImages;
}

// Count the size of the image list
double NydusImage::CountImagesSize(vector<NydusImage> &sourceImages, map<string, double> &globalChunkSize)
{
    double count = 0;
    for (int i = 0; i < sourceImages.size(); i++)
    {
        count += sourceImages[i].getImageSize(globalChunkSize);

        int actualChunk = sourceImages[i].imageStat.actualChunk;
        int chunkHashSize = sourceImages[i].chunkHash.size();
        assert(actualChunk == chunkHashSize);
    }
    return count;
}

// Analyze the Ociv1 image list
map<string, double> Ociv1Image::AnalyzeImages(vector<string> &fileList)
{
    int fileCount = fileList.size();
    map<string, double> hashs;
    double layerStorage = 0;
    int layerCount = 0;
    double imageSizeSum = 0;

    string sha256 = "sha256:";
    int len = sha256.length();
    for (int i = 0; i < fileCount; i++)
    {
        ifstream ifs(fileList[i]);
        json file;
        ifs >> file;

        double imageSize = file["image"]["sizeBytes"];
        imageSizeSum = imageSizeSum + imageSize / 1024 / 1024;

        int n = file["layer"].size();
        layerCount += n;
        for (int j = 0; j < n; j++)
        {
            json thislayer = file["layer"].at(j);
            string key = thislayer["digestId"];
            double value = thislayer["sizeBytes"];

            key = key.substr(len);
            value = value / 1024 / 1024;
            hashs[key] = value;
            layerStorage += value;
        }
    }

    int uniqueLayerCount = hashs.size();
    double optimizedLayerSizeSum = 0;
    for (const auto &kv : hashs)
    {
        optimizedLayerSizeSum += kv.second;
    }

    double ratio = 1 - (double)uniqueLayerCount / layerCount;
    double duplicatedLayerStorage = layerStorage - optimizedLayerSizeSum;
    double ratio2 = 1 - (double)optimizedLayerSizeSum / layerStorage;
    cout << "[Ociv1]" << endl;
    cout << "Layer Count: " << layerCount << " Unique Layer Count: " << uniqueLayerCount << endl;
    cout << "Layers that have been deduplicated in Ocv1: " << ratio * 100 << "%" << endl;
    cout << "The total size of each image: " << layerStorage << "MB" << endl;
    cout << "The total size of the duplicated layers: " << duplicatedLayerStorage << "MB" << endl;
    cout << "The Storage space occupied in the image registry: " << optimizedLayerSizeSum << "MB" << endl;
    cout << "Space saved by layer deduplication in Ociv1: " << ratio2 * 100 << "%" << endl;
    cout << "-----------------------------------------------------------" << endl;
    cout << endl;
    return hashs;
}

// The cost of referencing the base image in the business image
const double REFERENCE_COST_FACTOR = 0.01;

// Print BasicImageStat
int BasicImageStat::Print()
{
    string str = "MB\t";
    cout << basicSize << str << excludeSize << str << includeSize << str << REFERENCE_COST_FACTOR * includeSize << str << finalSize << str << oldSize << str << ratio * 100 << "%" << endl;
    return 0;
}

// Initialize BasicImageStat
int BasicImageStat::Init(map<string, int> &basicImage, vector<NydusImage> &sourceImages, map<string, double> &globalChunkSize)
{
    oldSize = NydusImage::CountImagesSize(sourceImages, globalChunkSize);
    vector<NydusImage> newImages = NydusImage::RebuildImage(basicImage, sourceImages);
    basicSize = GetImageRealSizeByHash(basicImage, globalChunkSize);
    excludeSize = NydusImage::CountImagesSize(newImages, globalChunkSize);
    includeSize = oldSize - excludeSize;

    finalSize = basicSize + excludeSize + REFERENCE_COST_FACTOR * includeSize;
    ratio = 1 - finalSize / oldSize;

    return 0;
}

// Getter with cache to save calculation cost
double BasicImage::getImageSize(map<string, double> &globalChunkSize)
{
    double result = 0.0;
    if (size < 0)
    {
        result = GetImageRealSizeByHash(chunkHash, globalChunkSize);
        size = result;
    }
    return size;
}

// Getter for chunkHash
map<string, int> BasicImage::getHashs()
{
    return chunkHash;
}

// Analyze the optimization effect of the reconstructed Nydus image
int BasicImage::compareWithBasicImage(BasicImage &basicImage, NydusImage &sourceImage, map<string, double> &globalChunkSize)
{
    map<string, int> hashs = sourceImage.getChunkHash();
    double sourceSize = sourceImage.getImageSize(globalChunkSize);
    double includeSize = 0;
    for (const auto &kv : hashs)
    {
        if (basicImage.chunkHash.find(kv.first) != basicImage.chunkHash.end())
        {
            includeSize += globalChunkSize[kv.first];
        }
    }
    double excludeSize = sourceSize - includeSize;
    double referenceSize = REFERENCE_COST_FACTOR * includeSize;
    double targetSize = excludeSize + referenceSize;
    double ratio = 1 - targetSize / sourceSize;
    string str = "MB\t";
    cout << sourceImage.getName() << "\t" << excludeSize << str << includeSize << str << referenceSize << str << targetSize << str << sourceSize << str << ratio * 100 << "%" << endl;
    return 0;
}

// Print the 4th report
int BasicImage::AnalyzeRebuildResult(BasicImage &basicImage, vector<NydusImage> &sourceImages, map<string, double> &globalChunkSize)
{
    int n = sourceImages.size();
    cout << "-----------------------------------------------------------" << endl;
    cout << "Table 4: Rebuild Optimization Results Report" << endl;
    cout << "Threshold: >=" << basicImage.threshold << "\t"
         << "(S)BasicImageSize: " << basicImage.getImageSize(globalChunkSize) << "MB" << endl;
    cout << "Image Name\t(a1)ExcludeSize\t(a2)IncludeSize\t(a3)ReferenceSize\t(A)targetSize\t(B)sourceSize\t(C)Ratio" << endl;
    for (int i = 0; i < n; i++)
    {
        compareWithBasicImage(basicImage, sourceImages[i], globalChunkSize);
    }
    cout << endl;
    cout << "Table 4 formula:" << endl;
    cout << "REFERENCE_COST_FACTOR = " << REFERENCE_COST_FACTOR << endl;
    cout << "a3 = REFERENCE_COST_FACTOR * a2" << endl;
    cout << "A = a1 + a3" << endl;
    cout << "C = 1 - A / B" << endl;
    cout << "-----------------------------------------------------------" << endl;
    cout << endl;
    return 0;
}

// Print the 3rd report
int BasicImage::PrintRebuildReport(vector<BasicImageStat> &statsList)
{
    cout << "-----------------------------------------------------------" << endl;
    cout << "Table 3: Image Rebuild Report" << endl;
    cout << "Threshold\t(a1)BasicImageSize\t(a2)ExcludeSize\t(a3)IncludeSize\t(a4)ReferenceSize\t(A)TotalCost\t(B)OldSize\t(C)Ratio" << endl;
    for (int i = 0; i < statsList.size(); i++)
    {
        cout << i + 1 << "\t";
        statsList[i].Print();
    }
    cout << endl;
    cout << "Table 3 formula:" << endl;
    cout << "REFERENCE_COST_FACTOR = " << REFERENCE_COST_FACTOR << endl;
    cout << "a4 = REFERENCE_COST_FACTOR * a3" << endl;
    cout << "A = a1 + a2 + a4" << endl;
    cout << "C = 1 - B / A" << endl;
    cout << "-----------------------------------------------------------" << endl;
    cout << endl;
    return 0;
}

// Analyze the regenerated base image
int BasicImage::AnalyzeRebuildImages(vector<NydusImage> &sourceImages, map<string, int> &globalChunkHash, map<string, double> &globalChunkSize)
{
    vector<BasicImage> basicImages;
    for (int i = 1; i <= sourceImages.size() + 1; i++)
    {
        BasicImage basicImage;
        basicImage.chunkHash = NydusImage::GenerateBasicImage(globalChunkHash, i);
        basicImage.threshold = i;
        basicImage.size = basicImage.getImageSize(globalChunkSize);
        basicImage.name = "basicImage" + to_string(i);

        basicImages.push_back(basicImage);
    }

    vector<BasicImageStat> statsList;
    for (int i = 0; i < basicImages.size(); i++)
    {
        auto hashs = basicImages[i].getHashs();
        BasicImageStat stats;
        stats.Init(hashs, sourceImages, globalChunkSize);
        statsList.push_back(stats);
    }

    BasicImage::PrintRebuildReport(statsList);

    int threshold = sourceImages.size() / 5;
    BasicImage::AnalyzeRebuildResult(basicImages[threshold - 1], sourceImages, globalChunkSize);

    return 0;
}

// Get all the files in the path and write them to the fileList
int GetAllFiles(string path, vector<string> &fileList)
{
    DIR *dir;
    struct dirent *ent;
    dir = opendir(path.c_str());

    if (!dir)
    {
        perror("Error");
        return 1;
    }

    // print all the files and directories within directory
    while ((ent = readdir(dir)) != NULL)
    {
        string fileName = ent->d_name;
        if (fileName != "." && fileName != "..")
        {
            string str;
            if (path.back() == '/' || path.back() == '\\')
            {
                str = path + fileName;
            }
            else
            {
                str = path + "/" + fileName;
            }
            fileList.push_back(str);
        }
    }

    // sort file list alphabetically
    sort(fileList.begin(), fileList.end());
    for (auto fileName : fileList)
    {
        cout << fileName << endl;
    }

    closedir(dir);
    return 0;
}

// Get all file names in the path
vector<string> ReadFileList(string path)
{
    cout << "Start Read File:" << endl;
    vector<string> fileList;
    if (GetAllFiles(path, fileList) != 0)
    {
        cout << "[ERROR] Open directory faild: " << path << endl;
        exit(-1);
    }

    int fileCount = fileList.size();
    cout << "File count: " << fileCount << endl;
    if (fileCount <= 0)
    {
        cout << "[ERROR] No file to analyze" << endl;
        exit(-2);
    }
    cout << endl;

    return fileList;
}

// Read and analyze image metadata
int ProcesseImages(string path)
{
    vector<string> fileList = ReadFileList(path + "/nydus");
    vector<string> jsonList = ReadFileList(path + "/ociv1_dive");
    vector<string> fileList2 = ReadFileList(path + "/nydus_new");

    map<string, double> globalChunkSize = NydusImage::InitChunkSizeMap(fileList2);

    auto result = NydusImage::AnalyzeImages(fileList, globalChunkSize);
    map<string, int> globalChunkHash = result.second;
    vector<NydusImage> images = result.first;

    map<string, double> Ociv1LayerSizes = Ociv1Image::AnalyzeImages(jsonList);

    BasicImage::AnalyzeRebuildImages(images, globalChunkHash, globalChunkSize);

    return 0;
}

// Output user manual
void Usage()
{
    cout << "Usage: nydus-stat [DirectoryName]" << endl;
    cout << "Default: nydus-stat data/example" << endl;
    cout << endl;
}

// Entry function of standard command line program
int main(int argc, char **argv)
{
    cout << "Nydus Stat v0.1.0" << endl;
    cout << endl;
    cout << fixed << setprecision(3);

    string path;
    if (argc == 2)
    {
        path = argv[1];
    }
    else
    {
        Usage();
        path = "data/example";
    }

    ProcesseImages(path);

    return 0;
}