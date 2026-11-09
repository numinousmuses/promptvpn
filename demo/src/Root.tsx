import React from "react";
import { Composition } from "remotion";
import { Overview, OVERVIEW_FRAMES } from "./Overview";
import { Entities, ENTITIES_FRAMES } from "./Entities";

export const RemotionRoot: React.FC = () => (
  <>
    <Composition id="Overview" component={Overview} durationInFrames={OVERVIEW_FRAMES} fps={30} width={1920} height={1080} />
    <Composition id="CustomEntities" component={Entities} durationInFrames={ENTITIES_FRAMES} fps={30} width={1920} height={1080} />
  </>
);
