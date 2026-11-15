package io.github.paxel.gates;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AdderTest {
  @Test
  void adds() {
    assertEquals(5, Adder.add(2, 3));
  }
}
