
running 1 test
Testing with 0 input jobs...
Generated Job Levels: 2
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTANoChange
RewardLevel=2
RewardIndex=0
Layer=1"];
  }
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 1 input jobs...
Generated Job Levels: 2
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 1"];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTAVerifyToCapWithCheckpointUpgrade
RewardLevel=2
RewardIndex=0
Layer=1"];
  }
  job_0_0 -> job_1_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTAVerifyToCapWithCheckpointUpgrade, group_id: 0, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 2 input jobs...
Generated Job Levels: 2
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 0"];
    job_0_1 [label="Input Proof 2
Checkpoint 1"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=2
RewardIndex=0
Layer=1"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTATwoGUTAWithCheckpointUpgrade, group_id: 0, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 3 input jobs...
Generated Job Levels: 3
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 1"];
    job_0_1 [label="Input Proof 2
Checkpoint 0"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 0"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=3
RewardIndex=0
Layer=1"];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint
RewardLevel=2
RewardIndex=0
Layer=2"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_1_0 -> job_2_0;
  job_0_2 -> job_2_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint, group_id: 1, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 4 input jobs...
Generated Job Levels: 3
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 1"];
    job_0_1 [label="Input Proof 2
Checkpoint 0"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 1"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 0"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=3
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=3
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=2
RewardIndex=0
Layer=2"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTATwoGUTALinear, group_id: 1, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 5 input jobs...
Generated Job Levels: 4
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 1"];
    job_0_1 [label="Input Proof 2
Checkpoint 0"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 1"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 0"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
    job_0_4 [label="Input Proof 5
Checkpoint 1"];
    job_0_3 -> job_0_4 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=0
Layer=2"];
  }
  subgraph level_3 {
    rank=same;
    job_3_0 [label="GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint
RewardLevel=2
RewardIndex=0
Layer=3"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
  job_2_0 -> job_3_0;
  job_0_4 -> job_3_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 6 input jobs...
Generated Job Levels: 4
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 0"];
    job_0_1 [label="Input Proof 2
Checkpoint 0"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 0"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 0"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
    job_0_4 [label="Input Proof 5
Checkpoint 1"];
    job_0_3 -> job_0_4 [style=invis, weight=2];
    job_0_5 [label="Input Proof 6
Checkpoint 1"];
    job_0_4 -> job_0_5 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
    job_1_2 [label="GUTATwoGUTA
RewardLevel=3
RewardIndex=1
Layer=1"];
    job_1_1 -> job_1_2 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=0
Layer=2"];
  }
  subgraph level_3 {
    rank=same;
    job_3_0 [label="GUTATwoGUTALinear
RewardLevel=2
RewardIndex=0
Layer=3"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_0_4 -> job_1_2;
  job_0_5 -> job_1_2;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
  job_2_0 -> job_3_0;
  job_1_2 -> job_3_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTATwoGUTALinear, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 7 input jobs...
Generated Job Levels: 4
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 0"];
    job_0_1 [label="Input Proof 2
Checkpoint 1"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 1"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 0"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
    job_0_4 [label="Input Proof 5
Checkpoint 0"];
    job_0_3 -> job_0_4 [style=invis, weight=2];
    job_0_5 [label="Input Proof 6
Checkpoint 0"];
    job_0_4 -> job_0_5 [style=invis, weight=2];
    job_0_6 [label="Input Proof 7
Checkpoint 0"];
    job_0_5 -> job_0_6 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
    job_1_2 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=2
Layer=1"];
    job_1_1 -> job_1_2 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=0
Layer=2"];
    job_2_1 [label="GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint
RewardLevel=3
RewardIndex=1
Layer=2"];
    job_2_0 -> job_2_1 [style=invis, weight=2];
  }
  subgraph level_3 {
    rank=same;
    job_3_0 [label="GUTATwoGUTALinear
RewardLevel=2
RewardIndex=0
Layer=3"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_0_4 -> job_1_2;
  job_0_5 -> job_1_2;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
  job_1_2 -> job_2_1;
  job_0_6 -> job_2_1;
  job_2_0 -> job_3_0;
  job_2_1 -> job_3_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTATwoGUTALinear, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 8 input jobs...
Generated Job Levels: 4
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 0"];
    job_0_1 [label="Input Proof 2
Checkpoint 1"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 1"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 0"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
    job_0_4 [label="Input Proof 5
Checkpoint 1"];
    job_0_3 -> job_0_4 [style=invis, weight=2];
    job_0_5 [label="Input Proof 6
Checkpoint 0"];
    job_0_4 -> job_0_5 [style=invis, weight=2];
    job_0_6 [label="Input Proof 7
Checkpoint 1"];
    job_0_5 -> job_0_6 [style=invis, weight=2];
    job_0_7 [label="Input Proof 8
Checkpoint 1"];
    job_0_6 -> job_0_7 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
    job_1_2 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=2
Layer=1"];
    job_1_1 -> job_1_2 [style=invis, weight=2];
    job_1_3 [label="GUTATwoGUTA
RewardLevel=4
RewardIndex=3
Layer=1"];
    job_1_2 -> job_1_3 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=0
Layer=2"];
    job_2_1 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=1
Layer=2"];
    job_2_0 -> job_2_1 [style=invis, weight=2];
  }
  subgraph level_3 {
    rank=same;
    job_3_0 [label="GUTATwoGUTALinear
RewardLevel=2
RewardIndex=0
Layer=3"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_0_4 -> job_1_2;
  job_0_5 -> job_1_2;
  job_0_6 -> job_1_3;
  job_0_7 -> job_1_3;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
  job_1_2 -> job_2_1;
  job_1_3 -> job_2_1;
  job_2_0 -> job_3_0;
  job_2_1 -> job_3_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTATwoGUTALinear, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 9 input jobs...
Generated Job Levels: 5
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 1"];
    job_0_1 [label="Input Proof 2
Checkpoint 0"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 0"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 1"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
    job_0_4 [label="Input Proof 5
Checkpoint 1"];
    job_0_3 -> job_0_4 [style=invis, weight=2];
    job_0_5 [label="Input Proof 6
Checkpoint 0"];
    job_0_4 -> job_0_5 [style=invis, weight=2];
    job_0_6 [label="Input Proof 7
Checkpoint 0"];
    job_0_5 -> job_0_6 [style=invis, weight=2];
    job_0_7 [label="Input Proof 8
Checkpoint 1"];
    job_0_6 -> job_0_7 [style=invis, weight=2];
    job_0_8 [label="Input Proof 9
Checkpoint 1"];
    job_0_7 -> job_0_8 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
    job_1_2 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=2
Layer=1"];
    job_1_1 -> job_1_2 [style=invis, weight=2];
    job_1_3 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=3
Layer=1"];
    job_1_2 -> job_1_3 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=4
RewardIndex=0
Layer=2"];
    job_2_1 [label="GUTATwoGUTALinear
RewardLevel=4
RewardIndex=1
Layer=2"];
    job_2_0 -> job_2_1 [style=invis, weight=2];
  }
  subgraph level_3 {
    rank=same;
    job_3_0 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=0
Layer=3"];
  }
  subgraph level_4 {
    rank=same;
    job_4_0 [label="GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint
RewardLevel=2
RewardIndex=0
Layer=4"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_0_4 -> job_1_2;
  job_0_5 -> job_1_2;
  job_0_6 -> job_1_3;
  job_0_7 -> job_1_3;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
  job_1_2 -> job_2_1;
  job_1_3 -> job_2_1;
  job_2_0 -> job_3_0;
  job_2_1 -> job_3_0;
  job_3_0 -> job_4_0;
  job_0_8 -> job_4_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint, group_id: 3, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 10 input jobs...
Generated Job Levels: 5
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 1"];
    job_0_1 [label="Input Proof 2
Checkpoint 0"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 1"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 0"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
    job_0_4 [label="Input Proof 5
Checkpoint 0"];
    job_0_3 -> job_0_4 [style=invis, weight=2];
    job_0_5 [label="Input Proof 6
Checkpoint 1"];
    job_0_4 -> job_0_5 [style=invis, weight=2];
    job_0_6 [label="Input Proof 7
Checkpoint 1"];
    job_0_5 -> job_0_6 [style=invis, weight=2];
    job_0_7 [label="Input Proof 8
Checkpoint 0"];
    job_0_6 -> job_0_7 [style=invis, weight=2];
    job_0_8 [label="Input Proof 9
Checkpoint 0"];
    job_0_7 -> job_0_8 [style=invis, weight=2];
    job_0_9 [label="Input Proof 10
Checkpoint 0"];
    job_0_8 -> job_0_9 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
    job_1_2 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=2
Layer=1"];
    job_1_1 -> job_1_2 [style=invis, weight=2];
    job_1_3 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=3
Layer=1"];
    job_1_2 -> job_1_3 [style=invis, weight=2];
    job_1_4 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=3
RewardIndex=1
Layer=1"];
    job_1_3 -> job_1_4 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=4
RewardIndex=0
Layer=2"];
    job_2_1 [label="GUTATwoGUTALinear
RewardLevel=4
RewardIndex=1
Layer=2"];
    job_2_0 -> job_2_1 [style=invis, weight=2];
  }
  subgraph level_3 {
    rank=same;
    job_3_0 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=0
Layer=3"];
  }
  subgraph level_4 {
    rank=same;
    job_4_0 [label="GUTATwoGUTALinear
RewardLevel=2
RewardIndex=0
Layer=4"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_0_4 -> job_1_2;
  job_0_5 -> job_1_2;
  job_0_6 -> job_1_3;
  job_0_7 -> job_1_3;
  job_0_8 -> job_1_4;
  job_0_9 -> job_1_4;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
  job_1_2 -> job_2_1;
  job_1_3 -> job_2_1;
  job_2_0 -> job_3_0;
  job_2_1 -> job_3_0;
  job_3_0 -> job_4_0;
  job_1_4 -> job_4_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTATwoGUTALinear, group_id: 3, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Testing with 11 input jobs...
Generated Job Levels: 5
graph viz:
digraph G {
  rankdir=BT;
  ordering=in;
  node [shape=box, fontname="Courier", fontsize=10];
  edge [color="black"];
  subgraph level_0 {
    rank=same;
    job_0_0 [label="Input Proof 1
Checkpoint 1"];
    job_0_1 [label="Input Proof 2
Checkpoint 0"];
    job_0_0 -> job_0_1 [style=invis, weight=2];
    job_0_2 [label="Input Proof 3
Checkpoint 1"];
    job_0_1 -> job_0_2 [style=invis, weight=2];
    job_0_3 [label="Input Proof 4
Checkpoint 1"];
    job_0_2 -> job_0_3 [style=invis, weight=2];
    job_0_4 [label="Input Proof 5
Checkpoint 1"];
    job_0_3 -> job_0_4 [style=invis, weight=2];
    job_0_5 [label="Input Proof 6
Checkpoint 0"];
    job_0_4 -> job_0_5 [style=invis, weight=2];
    job_0_6 [label="Input Proof 7
Checkpoint 0"];
    job_0_5 -> job_0_6 [style=invis, weight=2];
    job_0_7 [label="Input Proof 8
Checkpoint 1"];
    job_0_6 -> job_0_7 [style=invis, weight=2];
    job_0_8 [label="Input Proof 9
Checkpoint 1"];
    job_0_7 -> job_0_8 [style=invis, weight=2];
    job_0_9 [label="Input Proof 10
Checkpoint 0"];
    job_0_8 -> job_0_9 [style=invis, weight=2];
    job_0_10 [label="Input Proof 11
Checkpoint 1"];
    job_0_9 -> job_0_10 [style=invis, weight=2];
  }
  subgraph level_1 {
    rank=same;
    job_1_0 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=0
Layer=1"];
    job_1_1 [label="GUTATwoGUTA
RewardLevel=5
RewardIndex=1
Layer=1"];
    job_1_0 -> job_1_1 [style=invis, weight=2];
    job_1_2 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=2
Layer=1"];
    job_1_1 -> job_1_2 [style=invis, weight=2];
    job_1_3 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=5
RewardIndex=3
Layer=1"];
    job_1_2 -> job_1_3 [style=invis, weight=2];
    job_1_4 [label="GUTATwoGUTAWithCheckpointUpgrade
RewardLevel=4
RewardIndex=2
Layer=1"];
    job_1_3 -> job_1_4 [style=invis, weight=2];
  }
  subgraph level_2 {
    rank=same;
    job_2_0 [label="GUTATwoGUTALinear
RewardLevel=4
RewardIndex=0
Layer=2"];
    job_2_1 [label="GUTATwoGUTALinear
RewardLevel=4
RewardIndex=1
Layer=2"];
    job_2_0 -> job_2_1 [style=invis, weight=2];
    job_2_2 [label="GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint
RewardLevel=3
RewardIndex=1
Layer=2"];
    job_2_1 -> job_2_2 [style=invis, weight=2];
  }
  subgraph level_3 {
    rank=same;
    job_3_0 [label="GUTATwoGUTALinear
RewardLevel=3
RewardIndex=0
Layer=3"];
  }
  subgraph level_4 {
    rank=same;
    job_4_0 [label="GUTATwoGUTALinear
RewardLevel=2
RewardIndex=0
Layer=4"];
  }
  job_0_0 -> job_1_0;
  job_0_1 -> job_1_0;
  job_0_2 -> job_1_1;
  job_0_3 -> job_1_1;
  job_0_4 -> job_1_2;
  job_0_5 -> job_1_2;
  job_0_6 -> job_1_3;
  job_0_7 -> job_1_3;
  job_0_8 -> job_1_4;
  job_0_9 -> job_1_4;
  job_1_0 -> job_2_0;
  job_1_1 -> job_2_0;
  job_1_2 -> job_2_1;
  job_1_3 -> job_2_1;
  job_1_4 -> job_2_2;
  job_0_10 -> job_2_2;
  job_2_0 -> job_3_0;
  job_2_1 -> job_3_0;
  job_3_0 -> job_4_0;
  job_2_2 -> job_4_0;
}

Root Job ID: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 0, circuit_type: GUTATwoGUTALinear, group_id: 3, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
test guta_planner::coordinator_guta_planner::tests::demonstration_of_basic_functionality_you_need_to_make_tests ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 0.01s

