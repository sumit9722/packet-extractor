"""Deep SVDD on the ZedBoard: packet extractor and preprocessing on the PS, inference on the PL.

    packets -> FlowExtractor -> 8 raw features -> Preprocessor -> Q24 codes
            -> FpgaScorer (AXI DMA -> deep_svdd_axis) or Q24Model (software) -> score > threshold
"""
from .flows import FEATURES, FlowExtractor, FlowRecord, raw_features
from .model import Q24Model
from .pcap import LiveCapture, PcapReader
from .preprocess import Preprocessor

__all__ = ["FEATURES", "FlowExtractor", "FlowRecord", "raw_features", "Q24Model",
           "LiveCapture", "PcapReader", "Preprocessor"]
