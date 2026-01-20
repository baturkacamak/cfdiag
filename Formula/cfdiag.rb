class Cfdiag < Formula
  desc "Professional Cloudflare & Connectivity Diagnostic Tool"
  homepage "https://github.com/baturkacamak/cfdiag"
  url "https://github.com/baturkacamak/cfdiag/archive/refs/tags/v2.12.1.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on "python@3.10"

  def install
    # Install the script
    bin.install "cfdiag.py" => "cfdiag"
    # Install the man page
    man1.install "man/cfdiag.1"
  end

  test do
    system "#{bin}/cfdiag", "--version"
  end
end
