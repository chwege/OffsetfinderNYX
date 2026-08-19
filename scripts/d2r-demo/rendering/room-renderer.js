'use strict';

import { background } from 'gui';
import { projectSubtile } from './local-automap.js';

const ROOM_COLOR = 0x8048B8D8;
const ROOM_THICKNESS = 1.0;

export function clearRooms(roomKeys) {
  for (const key of roomKeys) background.remove(key);
  roomKeys.clear();
}

export function redrawRooms(rooms, roomKeys) {
  const nextKeys = new Set();

  for (let i = 0; i < rooms.length; i++) {
    const room = rooms[i];
    const points = [
      projectSubtile(room.minX, room.minY),
      projectSubtile(room.maxX, room.minY),
      projectSubtile(room.maxX, room.maxY),
      projectSubtile(room.minX, room.maxY),
    ];
    if (points.some(point => !point)) continue;

    for (let edge = 0; edge < 4; edge++) {
      const key = `map-room-${i}-${edge}`;
      const from = points[edge];
      const to = points[(edge + 1) % points.length];
      background.addLine(key, [from.x, from.y], [to.x, to.y], ROOM_COLOR, ROOM_THICKNESS);
      nextKeys.add(key);
    }
  }

  for (const key of roomKeys) {
    if (!nextKeys.has(key)) background.remove(key);
  }
  roomKeys.clear();
  for (const key of nextKeys) roomKeys.add(key);
  return nextKeys.size / 4;
}
