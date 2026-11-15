package io.github.paxel.gates;

/** Adds numbers. */
public final class Adder {
  private Adder() {}

  /** Adds two numbers, failing on overflow. */
  public static int add(int a, int b) {
    return Math.addExact(a, b);
  }
}
