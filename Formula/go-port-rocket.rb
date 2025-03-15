class GoPortRocket < Formula
  desc "高性能端口扫描器 | Fast Port Scanner"
  homepage "https://github.com/cyberspacesec/go-port-rocket"
  version "1.0.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/cyberspacesec/go-port-rocket/releases/download/v1.0.0/go-port-rocket_1.0.0_darwin_amd64.tar.gz"
    sha256 "PUT_ACTUAL_SHA256_HERE_AFTER_RELEASE"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/cyberspacesec/go-port-rocket/releases/download/v1.0.0/go-port-rocket_1.0.0_darwin_arm64.tar.gz"
    sha256 "PUT_ACTUAL_SHA256_HERE_AFTER_RELEASE"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/cyberspacesec/go-port-rocket/releases/download/v1.0.0/go-port-rocket_1.0.0_linux_amd64.tar.gz"
    sha256 "PUT_ACTUAL_SHA256_HERE_AFTER_RELEASE"
  elsif OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/cyberspacesec/go-port-rocket/releases/download/v1.0.0/go-port-rocket_1.0.0_linux_arm64.tar.gz"
    sha256 "PUT_ACTUAL_SHA256_HERE_AFTER_RELEASE"
  end

  depends_on "go" => :build
  depends_on "libpcap"

  def install
    # 对于已编译的二进制文件
    if build.stable?
      bin.install "go-port-rocket"
      return
    end

    # 如果需要从源代码构建
    system "go", "build", "-o", "go-port-rocket", "."
    bin.install "go-port-rocket"
  end

  test do
    assert_match "go-port-rocket", shell_output("#{bin}/go-port-rocket --version")
  end
end 