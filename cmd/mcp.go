package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cyberspacesec/go-port-rocket/pkg/mcp"
	"github.com/spf13/cobra"
)

// mcpCmd MCP命令
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "使用Model Context Protocol",
	Long:  `使用Model Context Protocol进行端口扫描和网络安全分析，支持基于上下文的自然语言理解。`,
	Run:   runMCP,
}

func init() {
	// 添加MCP命令参数
	mcpCmd.Flags().BoolVar(&Modelcp_StartSession, "start-session", false, "启动一个新的MCP会话")
	mcpCmd.Flags().StringVar(&Modelcp_SessionID, "session-id", "", "指定MCP会话ID")
	mcpCmd.Flags().StringVar(&Modelcp_Query, "query", "", "自然语言查询")
	mcpCmd.Flags().BoolVar(&Modelcp_ConfigModel, "config-model", false, "配置AI模型")
	mcpCmd.Flags().StringVar(&Modelcp_ConfigType, "type", "openai", "AI模型类型 (openai, local)")
	mcpCmd.Flags().StringVar(&Modelcp_ApiKey, "api-key", "", "AI服务API密钥")
	mcpCmd.Flags().StringVar(&Modelcp_Model, "model", "gpt-4", "AI模型名称")
	mcpCmd.Flags().BoolVar(&Modelcp_ShowHistory, "show-history", false, "显示会话历史")
	mcpCmd.Flags().BoolVar(&Modelcp_ExportSession, "export-session", false, "导出会话")
	mcpCmd.Flags().StringVar(&Modelcp_ImportFile, "import", "", "导入会话文件")
	mcpCmd.Flags().StringVar(&Modelcp_OutputFile, "output", "", "输出文件路径")
	mcpCmd.Flags().StringVar(&Modelcp_OutputFormat, "output-format", "text", "输出格式 (text, json)")

	// 添加MCP命令到根命令
	RootCmd.AddCommand(mcpCmd)
}

// runMCP 运行MCP命令
func runMCP(cmd *cobra.Command, args []string) {
	// 创建MCP协议实例
	protocol := mcp.NewProtocol()

	// 导入会话
	if Modelcp_ImportFile != "" {
		data, err := ioutil.ReadFile(Modelcp_ImportFile)
		if err != nil {
			fmt.Printf("错误: 读取会话文件失败: %v\n", err)
			os.Exit(1)
		}

		sessionID, err := protocol.ImportSession(data)
		if err != nil {
			fmt.Printf("错误: 导入会话失败: %v\n", err)
			os.Exit(1)
		}

		// 导入成功后设置当前会话ID
		Modelcp_SessionID = sessionID
		fmt.Printf("已导入会话: %s\n", sessionID)
	}

	// 启动新会话
	if Modelcp_StartSession {
		sessionID, err := protocol.CreateSession()
		if err != nil {
			fmt.Printf("错误: 创建会话失败: %v\n", err)
			os.Exit(1)
		}

		Modelcp_SessionID = sessionID
		fmt.Printf("会话已创建: %s\n", sessionID)
	}

	// 配置AI模型
	if Modelcp_ConfigModel {
		if Modelcp_SessionID == "" {
			// 如果没有指定会话ID，则创建一个新会话
			sessionID, err := protocol.CreateSession()
			if err != nil {
				fmt.Printf("错误: 创建会话失败: %v\n", err)
				os.Exit(1)
			}
			Modelcp_SessionID = sessionID
			fmt.Printf("会话已创建: %s\n", sessionID)
		}

		// 获取会话
		session, err := protocol.GetSession(Modelcp_SessionID)
		if err != nil {
			fmt.Printf("错误: 获取会话失败: %v\n", err)
			os.Exit(1)
		}

		// 设置AI模型配置
		context := session.GetContext()
		context.SetEnvironment("model_type", Modelcp_ConfigType)
		context.SetEnvironment("api_key", Modelcp_ApiKey)
		context.SetEnvironment("model", Modelcp_Model)

		fmt.Printf("AI模型已配置: %s (%s)\n", Modelcp_Model, Modelcp_ConfigType)
	}

	// 显示会话历史
	if Modelcp_ShowHistory {
		if Modelcp_SessionID == "" {
			fmt.Println("错误: 请指定会话ID")
			os.Exit(1)
		}

		// 获取会话
		session, err := protocol.GetSession(Modelcp_SessionID)
		if err != nil {
			fmt.Printf("错误: 获取会话失败: %v\n", err)
			os.Exit(1)
		}

		// 显示历史记录
		context := session.GetContext()
		history := context.History
		fmt.Printf("会话 %s 的历史记录 (%d 条):\n", Modelcp_SessionID, len(history))
		for i, instruction := range history {
			fmt.Printf("%d. [%s/%s] %s\n", i+1, instruction.Type, instruction.Intent, instruction.Query)
		}
	}

	// 导出会话
	if Modelcp_ExportSession {
		if Modelcp_SessionID == "" {
			fmt.Println("错误: 请指定会话ID")
			os.Exit(1)
		}

		// 导出会话
		data, err := protocol.ExportSession(Modelcp_SessionID)
		if err != nil {
			fmt.Printf("错误: 导出会话失败: %v\n", err)
			os.Exit(1)
		}

		// 写入文件
		if Modelcp_OutputFile != "" {
			if err := ioutil.WriteFile(Modelcp_OutputFile, data, 0644); err != nil {
				fmt.Printf("错误: 写入会话文件失败: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("会话已导出到: %s\n", Modelcp_OutputFile)
		} else {
			fmt.Printf("会话数据: %s\n", string(data))
		}
	}

	// 处理查询
	if Modelcp_Query != "" {
		// 处理自然语言查询
		response, err := protocol.ProcessQuery(Modelcp_Query, Modelcp_SessionID)
		if err != nil {
			fmt.Printf("错误: 处理查询失败: %v\n", err)
			os.Exit(1)
		}

		// 输出响应
		if Modelcp_OutputFormat == "json" {
			// 输出 JSON 格式
			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				fmt.Printf("错误: 序列化响应失败: %v\n", err)
				os.Exit(1)
			}

			if Modelcp_OutputFile != "" {
				if err := ioutil.WriteFile(Modelcp_OutputFile, jsonData, 0644); err != nil {
					fmt.Printf("错误: 写入输出文件失败: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("结果已保存到: %s\n", Modelcp_OutputFile)
			} else {
				fmt.Println(string(jsonData))
			}
		} else {
			// 输出文本格式
			output := fmt.Sprintf("状态: %s\n", response.Status)
			if response.Message != "" {
				output += fmt.Sprintf("消息: %s\n", response.Message)
			}

			if response.Data != nil {
				output += "\n数据:\n"
				// 处理数据
				if target, ok := response.Data["target"]; ok {
					output += fmt.Sprintf("目标: %v\n", target)
				}
				if ports, ok := response.Data["ports"]; ok {
					output += "发现端口:\n"
					if portsSlice, ok := ports.([]map[string]interface{}); ok {
						for _, port := range portsSlice {
							output += fmt.Sprintf("- %v/%v (%v): %v\n",
								port["port"], port["protocol"], port["state"], port["service"])
						}
					}
				}
			}

			if response.Analysis != nil {
				output += "\n分析:\n"
				// 处理分析结果
				if overview, ok := response.Analysis["overview"]; ok {
					output += fmt.Sprintf("%v\n", overview)
				}
				if issues, ok := response.Analysis["security_issues"]; ok {
					if issuesSlice, ok := issues.([]map[string]interface{}); ok {
						output += "\n安全问题:\n"
						for _, issue := range issuesSlice {
							output += fmt.Sprintf("- [%v] %v: %v\n",
								issue["severity"], issue["service"], issue["issue"])
							if rec, ok := issue["recommendation"]; ok {
								output += fmt.Sprintf("  建议: %v\n", rec)
							}
						}
					}
				}
				if riskLevel, ok := response.Analysis["risk_level"]; ok {
					output += fmt.Sprintf("\n风险级别: %v\n", riskLevel)
				}
			}

			if len(response.NextSteps) > 0 {
				output += "\n建议操作:\n"
				for i, step := range response.NextSteps {
					output += fmt.Sprintf("%d. %s\n", i+1, step)
				}
			}

			if Modelcp_OutputFile != "" {
				if err := ioutil.WriteFile(Modelcp_OutputFile, []byte(output), 0644); err != nil {
					fmt.Printf("错误: 写入输出文件失败: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("结果已保存到: %s\n", Modelcp_OutputFile)
			} else {
				fmt.Println(output)
			}
		}

		// 显示当前会话ID
		if Modelcp_SessionID == "" && response.SessionID != "" {
			fmt.Printf("\n注意: 已创建新会话: %s\n", response.SessionID)
		}
	}
}
