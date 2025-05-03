#include "MIMEType.hh"

#include <stdexcept>
#include <string>
#include <unordered_map>

using namespace std;

static const unordered_map<string, string> mime_type_for_file_extension({
    {"aif", "audio/aiff"},
    {"aifc", "audio/aiff"},
    {"aiff", "audio/aiff"},
    {"ani", "application/x-navi-animation"},
    {"asf", "video/x-ms-asf"},
    {"asm", "text/x-asm"},
    {"asp", "text/asp"},
    {"asx", "video/x-ms-asf"},
    {"au", "audio/basic"},
    {"avi", "video/avi"},
    {"bm", "image/bmp"},
    {"bmp", "image/bmp"},
    {"dib", "image/bmp"},
    {"bz", "application/x-bzip"},
    {"bz2", "application/x-bzip2"},
    {"c", "text/x-c"},
    {"cc", "text/x-cplusplus"},
    {"class", "application/java"},
    {"conf", "text/plain"},
    {"cpp", "text/x-cplusplus"},
    {"crt", "application/pkix-cert"},
    {"csh", "text/x-script.csh"},
    {"css", "text/css"},
    {"cxx", "text/x-cplusplus"},
    {"doc", "application/msword"},
    {"dv", "video/x-dv"},
    {"dvi", "application/x-dvi"},
    {"eps", "application/postscript"},
    {"f", "text/x-fortran"},
    {"f77", "text/x-fortran"},
    {"f90", "text/x-fortran"},
    {"gif", "image/gif"},
    {"gitignore", "text/plain"},
    {"gz", "application/x-gzip"},
    {"gzip", "multipart/x-gzip"},
    {"h", "text/x-c"},
    {"hh", "text/x-cplusplus"},
    {"hpp", "text/x-cplusplus"},
    {"hqx", "application/binhex"},
    {"htm", "text/html"},
    {"html", "text/html"},
    {"htmls", "text/html"},
    {"hxx", "text/x-cplusplus"},
    {"ico", "image/x-icon"},
    {"it", "audio/it"},
    {"jav", "text/x-java-source"},
    {"java", "text/x-java-source"},
    {"jfif", "image/jpeg"},
    {"jpe", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"jpg", "image/jpeg"},
    {"js", "text/javascript"},
    {"json", "application/json"},
    {"ksh", "text/x-script.ksh"},
    {"latex", "application/x-latex"},
    {"log", "text/plain"},
    {"m", "text/plain"},
    {"m1v", "video/mpeg"},
    {"m2a", "audio/mpeg"},
    {"m2v", "video/mpeg"},
    {"man", "application/x-troff-man"},
    {"md", "text/markdown"},
    {"mid", "audio/midi"},
    {"midi", "audio/midi"},
    {"mod", "audio/mod"},
    {"moov", "video/quicktime"},
    {"mov", "video/quicktime"},
    {"mp2", "video/mpeg"},
    {"mp3", "audio/mpeg3"},
    {"mpe", "video/mpeg"},
    {"mpeg", "video/mpeg"},
    {"mpg", "video/mpeg"},
    {"p", "text/pascal"},
    {"p10", "application/pkcs10"},
    {"p12", "application/pkcs-12"},
    {"p7a", "application/x-pkcs7-signature"},
    {"p7c", "application/x-pkcs7-mime"},
    {"p7m", "application/x-pkcs7-mime"},
    {"p7r", "application/x-pkcs7-certreqresp"},
    {"p7s", "application/pkcs7-signature"},
    {"pas", "text/x-pascal"},
    {"pbm", "image/x-portable-bitmap"},
    {"pct", "image/x-pict"},
    {"pcx", "image/x-pcx"},
    {"pdf", "application/pdf"},
    {"pgm", "image/x-portable-greymap"},
    {"php", "text/x-php"},
    {"php5", "text/x-php"},
    {"phps", "text/x-php"},
    {"pic", "image/pict"},
    {"pict", "image/pict"},
    {"pkg", "application/x-newton-compatible-pkg"},
    {"pl", "text/x-script.perl"},
    {"png", "image/png"},
    {"pnm", "image/x-portable-anymap"},
    {"ppm", "image/x-portable-pixmap"},
    {"ppt", "application/x-mspowerpoint"},
    {"ps", "application/postscript"},
    {"py", "text/x-script.python"},
    {"py2", "text/x-script.python"},
    {"py3", "text/x-script.python"},
    {"pyc", "application/x-bytecode.python"},
    {"pyo", "application/x-bytecode.python"},
    {"qt", "video/quicktime"},
    {"ra", "audio/x-realaudio"},
    {"ram", "audio/x-realaudio"},
    {"rm", "audio/x-pn-realaudio"},
    {"rtf", "application/rtf"},
    {"S", "text/x-asm"},
    {"s", "text/x-asm"},
    {"s3m", "audio/s3m"},
    {"sea", "application/sea"},
    {"sh", "text/x-script.sh"},
    {"shtml", "text/html"},
    {"snd", "audio/basic"},
    {"svg", "image/svg+xml"},
    {"swf", "application/x-shockwave-flash"},
    {"t", "application/x-troff"},
    {"tar", "application/x-tar"},
    {"tcl", "text/x-script.tcl"},
    {"tcsh", "text/x-script.tcsh"},
    {"tex", "application/x-tex"},
    {"text", "text/plain"},
    {"tgz", "application/x-compressed"},
    {"tif", "image/tiff"},
    {"tiff", "image/tiff"},
    {"tr", "application/x-troff"},
    {"tsv", "text/tab-separated-values"},
    {"txt", "text/plain"},
    {"wav", "audio/wav"},
    {"xm", "audio/xm"},
    {"xml", "text/xml"},
    {"yaml", "text/yaml"},
    {"yml", "text/yaml"},
    {"z", "application/x-compressed"},
    {"zip", "application/x-compressed"},
    {"zsh", "text/x-script.zsh"},
});

static const unordered_map<string, string> mime_type_for_basename({
    {"LICENSE", "text/plain"},
    {"Makefile", "text/plain"},
    {"README", "text/plain"},
});

const char* mime_type_for_filename(const string& filename) {
  size_t extension_pos = filename.rfind('.');
  if (extension_pos != string::npos) {
    try {
      string extension = filename.substr(extension_pos + 1);
      return mime_type_for_file_extension.at(extension).c_str();
    } catch (const out_of_range& e) {
    }
  }

  // some common (usually text) files don't have extensions
  size_t slash_pos = filename.rfind('/');
  if (slash_pos != string::npos) {
    try {
      string basename = filename.substr(slash_pos + 1);
      return mime_type_for_basename.at(basename).c_str();
    } catch (const out_of_range& e) {
    }
  } else {
    try {
      return mime_type_for_basename.at(filename).c_str();
    } catch (const out_of_range& e) {
    }
  }

  return "application/octet-stream";
}
