# 智安学护 - 大学生个人信息风险控制系统

## 项目简介

智安学护是一个面向大学生的全生命周期风控体系系统，融合事前自查、事中预警、事后核验三大核心能力，帮助大学生有效防范个人信息泄露、诈骗等风险。

## 核心功能

### 管理端
- **总览大屏**：全校安全态势可视化展示
- **风险报告**：AI分析生成风险报告，支持导出
- **预警推送**：实时预警信息管理与处理
- **学生管理**：学生风控画像与档案管理
- **AI模型中心**：三大核心风控模型演示

### 学生端
- **信息泄露自查**：HIBP数据库泄露检测
- **贷款冒用核验**：征信时序监测
- **反诈预警**：BERT诈骗话术识别
- **安全知识问答**：防骗能力测试

## 技术架构

- **后端**：Express.js 5.x + SQLite3
- **前端**：原生HTML5 + Tailwind CSS + ECharts
- **AI模型**：BERT诈骗话术识别、随机森林异常行为检测、时序分析贷款冒用检测
- **安全机制**：bcryptjs密码加密、express-session会话管理、RBAC权限控制

## 部署方式

### 方式一：Render部署（推荐免费方案）

1. 注册 [Render](https://render.com) 账号
2. 创建新的 Web Service
3. 连接你的GitHub仓库
4. 配置：
   - Build Command: `npm install`
   - Start Command: `npm start`
5. 部署完成后获得公开访问链接

### 方式二：Railway部署

1. 注册 [Railway](https://railway.app) 账号
2. 创建新项目，选择从GitHub部署
3. 配置启动命令：`npm start`
4. 获取公开链接

### 方式三：本地运行

```bash
# 1. 克隆项目
git clone https://github.com/你的用户名/zhianxuehu.git

# 2. 进入项目目录
cd zhianxuehu/project

# 3. 安装依赖
npm install

# 4. 启动服务
npm start

# 5. 访问系统
# 打开浏览器访问 http://localhost:3000/gate.html
```

## 默认账号

| 角色 | 用户名 | 密码 |
|------|--------|------|
| 管理员 | admin | 123456 |
| 学生 | chenyaohua | 123456 |

## 项目结构

```
project/
├── server.js          # 后端主文件
├── package.json       # 项目配置
├── zhianxuehu.db      # SQLite数据库（运行时创建）
├── public/            # 前端文件
│   ├── gate.html      # 入口页面
│   ├── admin-*.html   # 管理端页面
│   ├── student-*.html # 学生端页面
│   └── common.js      # 公共脚本
└── README.md          # 项目说明
```

## 注意事项

- SQLite数据库在首次运行时自动创建并初始化数据
- 生产环境建议修改默认密码
- 建议配置环境变量管理敏感信息

## 许可证

MIT License