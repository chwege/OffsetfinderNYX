'use strict';

import { io } from 'gui';

const MAP_WIDTH_RATIO = 0.82;
const MAP_HEIGHT_RATIO = 0.78;
const MIN_VIEWPORT_SIZE = 64;
const MAX_COORD = 1000000;

let projection = null;

function subtileToClient(subX, subY) {
  return { x: (subX - subY) * 16, y: (subX + subY) * 8 };
}

function validNumber(value) {
  return Number.isFinite(value) && Math.abs(value) <= MAX_COORD;
}

export function configureLocalAutomap(bounds) {
  const display = io.displaySize;
  const width = Number(display?.x);
  const height = Number(display?.y);
  if (!bounds || width < MIN_VIEWPORT_SIZE || height < MIN_VIEWPORT_SIZE) {
    projection = null;
    return null;
  }

  const values = [bounds.minX, bounds.minY, bounds.maxX, bounds.maxY];
  if (!values.every(validNumber) || bounds.maxX <= bounds.minX || bounds.maxY <= bounds.minY) {
    projection = null;
    return null;
  }

  const corners = [
    subtileToClient(bounds.minX, bounds.minY),
    subtileToClient(bounds.maxX, bounds.minY),
    subtileToClient(bounds.maxX, bounds.maxY),
    subtileToClient(bounds.minX, bounds.maxY),
  ];
  const minClientX = Math.min(...corners.map(p => p.x));
  const maxClientX = Math.max(...corners.map(p => p.x));
  const minClientY = Math.min(...corners.map(p => p.y));
  const maxClientY = Math.max(...corners.map(p => p.y));
  const clientWidth = Math.max(1, maxClientX - minClientX);
  const clientHeight = Math.max(1, maxClientY - minClientY);

  projection = {
    width,
    height,
    centerX: width * 0.5,
    centerY: height * 0.5,
    clientCenterX: (minClientX + maxClientX) * 0.5,
    clientCenterY: (minClientY + maxClientY) * 0.5,
    scale: Math.min(
      width * MAP_WIDTH_RATIO / clientWidth,
      height * MAP_HEIGHT_RATIO / clientHeight,
    ),
  };
  return { ...projection };
}

export function clearLocalAutomap() {
  projection = null;
}

export function getLocalAutomapProjection() {
  return projection ? { ...projection } : null;
}

export function viewportChanged() {
  if (!projection) return false;
  const display = io.displaySize;
  return Number(display?.x) !== projection.width || Number(display?.y) !== projection.height;
}

export function projectClient(clientX, clientY) {
  if (!projection || !validNumber(clientX) || !validNumber(clientY)) return null;
  const x = projection.centerX + (clientX - projection.clientCenterX) * projection.scale;
  const y = projection.centerY + (clientY - projection.clientCenterY) * projection.scale;
  if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
  return { x: Math.round(x), y: Math.round(y) };
}

export function projectSubtile(subX, subY) {
  if (!validNumber(subX) || !validNumber(subY)) return null;
  const client = subtileToClient(subX, subY);
  return projectClient(client.x, client.y);
}
