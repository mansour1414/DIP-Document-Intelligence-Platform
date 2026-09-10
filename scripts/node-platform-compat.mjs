// tsx derives its temp directory from process.geteuid() on Unix and os.userInfo()
// on Windows. Some locked-down Windows runners cannot resolve os.userInfo().
if (process.platform === "win32" && typeof process.geteuid !== "function") {
  process.geteuid = () => 0;
}
