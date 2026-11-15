package io.github.paxel.gates;

/** Adds numbers. */
public final class Adder {
  private Adder() {}

  /** Adds two numbers; the planted finding is an exception created and never thrown. */
  public static int add(int a, int b) {
    if (a < 0) {
      new IllegalArgumentException("negative");
    }
    return Math.addExact(a, b);
  }
}
