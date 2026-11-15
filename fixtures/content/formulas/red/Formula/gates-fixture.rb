class GatesFixture < Formula
  desc "A formula fixture whose description starts with an article, which brew audit rejects"
  homepage "https://github.com/paxel/gates"
  url "https://github.com/paxel/gates/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "1f7ab5ee1b2e0a7a2d1b6ab0ac0f9c6e1e2b3c4d5e6f708192a3b4c5d6e7f809"
  license "MIT"

  def install
    bin.install "README.md" => "gates-fixture"
  end

  test do
    assert_path_exists bin/"gates-fixture"
  end
end
