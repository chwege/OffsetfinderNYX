'use strict';

const { Unit } = require('d2r/unit');

class WorldObject extends Unit {
  constructor() {
    super();
    this.automapX = -1;
    this.automapY = -1;
  }
}

module.exports = { WorldObject };
