import json
import logging
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, START, END

# Import schemas từ thư mục shared theo chuẩn đã thống nhất
from shared.schemas import ScannerOutput, AgentRunOutput, PatchResult, RawAlert
from core.prompts.prompts import ANALYZE_VULNERABILITY_PROMPT, GENERATE_PATCH_PROMPT

# Cấu hình log cơ bản
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# 1. ĐỊNH NGHĨA TRẠNG THÁI (STATE) CHO ĐỒ THỊ LANGGRAPH
# ============================================================================
class DevSecOpsState(TypedDict):
    scanner_input: ScannerOutput
    current_alerts: List[RawAlert]
    patch_results: List[PatchResult]
    final_output: AgentRunOutput

# ============================================================================
# 2. CÁC NODE CỦA ĐỒ THỊ (GRAPH NODES)
# ============================================================================
def init_state(state: DevSecOpsState):
    """Khởi tạo trạng thái đầu vào"""
    logger.info("Bắt đầu xử lý luồng AI DevSecOps")
    return {
        "current_alerts": state["scanner_input"].alerts,
        "patch_results": []
    }

def analyze_alerts(state: DevSecOpsState):
    """Lọc báo ảo (False Positive) bằng LLM"""
    alerts = state.get("current_alerts", [])
    results = state.get("patch_results", [])
    
    logger.info(f"Đang phân tích {len(alerts)} cảnh báo bảo mật...")
    
    # TODO: Tích hợp llm_client thực tế ở đây
    # For now, we mock the logic (Giả lập logic)
    for alert in alerts:
        # call llm_client here with ANALYZE_VULNERABILITY_PROMPT
        # response = invoke_llm(llm, prompt)
        
        # Giả lập LLM luôn trả về là lỗi thật (is_real_vulnerability = True) để tiếp tục bước vá
        patch_result = PatchResult(
            file_path=alert.file_path,
            cwe_id=alert.cwe_id,
            is_real_vulnerability=True, 
            confidence_score=0.9,
            explanation="Phát hiện lỗi SQL Injection do nối chuỗi trực tiếp."
        )
        
        # Chuyển dữ liệu mã nguồn tạm vào explanation (hoặc mở rộng PatchResult) để truyền cho node sau
        setattr(patch_result, "_temp_code_snippet", alert.code_snippet)
        
        results.append(patch_result)
        
    return {"patch_results": results}

def generate_patches(state: DevSecOpsState):
    """Sinh bản vá cho các lỗi được xác định là có thật (True Positive)"""
    results = state.get("patch_results", [])
    
    logger.info("Đang sinh bản vá cho các lỗi thực sự...")
    
    for res in results:
        if res.is_real_vulnerability:
            # call llm_client here with GENERATE_PATCH_PROMPT
            code = getattr(res, "_temp_code_snippet", "")
            
            # Giả lập sinh code vá
            res.patch_diff = f"- {code}\n+ // Mã đã được vá an toàn\n"
            res.remediation_advice = "Sử dụng Parametrized Queries."
            
    return {"patch_results": results}

def format_output(state: DevSecOpsState):
    """Tổng hợp kết quả trả về cho LÂM (Git Bot)"""
    results = state.get("patch_results", [])
    
    total_real = sum(1 for r in results if r.is_real_vulnerability)
    total_false = len(results) - total_real
    
    output = AgentRunOutput(
        commit_hash=state["scanner_input"].commit_hash,
        total_real_vulnerabilities=total_real,
        total_false_positives=total_false,
        results=results
    )
    
    logger.info("Hoàn tất xử lý, chuẩn bị trả dữ liệu qua shared schemas")
    return {"final_output": output}

# ============================================================================
# 3. XÂY DỰNG ĐỒ THỊ (BUILD THE GRAPH)
# ============================================================================
def build_devsecops_graph():
    workflow = StateGraph(DevSecOpsState)
    
    # Thêm các nodes
    workflow.add_node("init", init_state)
    workflow.add_node("analyze", analyze_alerts)
    workflow.add_node("patch", generate_patches)
    workflow.add_node("format", format_output)
    
    # Định nghĩa luồng (edges)
    workflow.add_edge(START, "init")
    workflow.add_edge("init", "analyze")
    workflow.add_edge("analyze", "patch")
    workflow.add_edge("patch", "format")
    workflow.add_edge("format", END)
    
    # Compile
    app = workflow.compile()
    return app

# Hàm public để các module khác gọi
def run_ai_core(scanner_output: ScannerOutput) -> AgentRunOutput:
    """Hàm giao tiếp chính thức của module core (dành cho PHÚC)"""
    app = build_devsecops_graph()
    
    initial_state = {"scanner_input": scanner_output}
    final_state = app.invoke(initial_state)
    
    return final_state["final_output"]
