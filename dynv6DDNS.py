#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import requests
import json
import time
import sys
import ipaddress
import re
import subprocess
from typing import Optional, Tuple

try:
    from notify import send
except ImportError:
    print("❌ 无法导入青龙面板通知模块，请确保在青龙面板中运行")
    sys.exit(1)

class DynV6DDNS:
    def __init__(self):
        # 从环境变量获取配置
        self.domain = os.getenv('DYNV6_DOMAIN', '').strip()
        self.token = os.getenv('DYNV6_TOKEN', '').strip()
        self.enable_ipv4 = os.getenv('DYNV6_IPV4', 'true').lower() == 'true'
        self.enable_ipv6 = os.getenv('DYNV6_IPV6', 'true').lower() == 'true'
        self.check_interval = int(os.getenv('DYNV6_CHECK_INTERVAL', '60'))
        
        # IP获取方式配置
        self.ip_source = os.getenv('DYNV6_IP_SOURCE', 'public_api').strip().lower()
        self.interface_mac = os.getenv('DYNV6_INTERFACE_MAC', '').strip()
        self.interface_name = os.getenv('DYNV6_INTERFACE_NAME', '').strip()
        
        # IP存储文件路径（用于比较IP变化）
        self.last_ip_file = os.getenv('DYNV6_LAST_IP_FILE', '/ql/data/scripts/dynv6_last_ips.json')
        
        # 确保存储目录存在
        os.makedirs(os.path.dirname(self.last_ip_file), exist_ok=True)
        
        # IP获取API列表
        self.ipv4_apis = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://ifconfig.me/ip',
            'https://ipv4.seeip.org',
            'https://ipinfo.io/ip'
        ]
        
        self.ipv6_apis = [
            'https://api6.ipify.org',
            'https://ident.me',
            'https://ifconfig.me/ip',
            'https://ipv6.seeip.org',
            'https://ipinfo.io/ip'
        ]

    def load_last_ips(self) -> dict:
        """加载上次存储的IP地址[3](@ref)"""
        try:
            if os.path.exists(self.last_ip_file):
                with open(self.last_ip_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"⚠️  读取上次IP记录失败: {e}")
        return {"ipv4": "", "ipv6": ""}

    def save_current_ips(self, ipv4: str, ipv6: str):
        """保存当前IP地址到文件[3](@ref)"""
        try:
            with open(self.last_ip_file, 'w') as f:
                json.dump({"ipv4": ipv4 or "", "ipv6": ipv6 or ""}, f)
            print("✅ 当前IP地址已保存")
        except Exception as e:
            print(f"⚠️  保存IP记录失败: {e}")

    def validate_ip_address(self, ip: str, ip_version: int) -> bool:
        """严格验证IP地址格式"""
        try:
            if ip_version == 4:
                ipaddress.IPv4Address(ip)
                return True
            elif ip_version == 6:
                ipaddress.IPv6Address(ip)
                return True
        except ipaddress.AddressValueError:
            return False
        return False

    def get_interface_ipv4_address(self) -> Optional[str]:
        """从网卡获取IPv4地址"""
        try:
            if sys.platform == "win32":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    output = result.stdout
                    ipv4_pattern = r'IPv4 Address[^:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
                    matches = re.findall(ipv4_pattern, output, re.IGNORECASE)
                    for ip in matches:
                        if not ip.startswith(('169.254', '127.', '10.', '192.168', '172.')):
                            if self.validate_ip_address(ip, 4):
                                print(f"✅ 从网卡获取IPv4地址: {ip}")
                                return ip
            else:
                result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    output = result.stdout
                    ipv4_pattern = r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                    matches = re.findall(ipv4_pattern, output)
                    public_ips = []
                    for ip in matches:
                        if not ip.startswith(('127.', '10.', '192.168', '172.')):
                            if self.validate_ip_address(ip, 4):
                                public_ips.append(ip)
                    if public_ips:
                        print(f"✅ 从网卡获取IPv4地址: {public_ips[0]}")
                        return public_ips[0]
        except Exception as e:
            print(f"⚠️  从网卡获取IPv4地址失败: {e}")
        return None

    def get_interface_ipv6_address(self) -> Optional[str]:
        """从网卡获取IPv6地址[3](@ref)"""
        try:
            if sys.platform == "win32":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    output = result.stdout
                    ipv6_pattern = r'IPv6 Address[^:]*:\s*([0-9a-fA-F:]+)'
                    matches = re.findall(ipv6_pattern, output, re.IGNORECASE)
                    for ip in matches:
                        if not ip.startswith(('fe80:', 'fc', 'fd')):
                            if self.validate_ip_address(ip, 6):
                                print(f"✅ 从网卡获取IPv6地址: {ip}")
                                return ip
            else:
                result = subprocess.run(['ip', '-6', 'addr', 'show'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    output = result.stdout
                    interfaces = {}
                    current_interface = None
                    
                    for line in output.splitlines():
                        if line.strip().startswith(('1:', '2:', '3:', '10:')):
                            parts = line.split(':')
                            if len(parts) > 1:
                                current_interface = parts[1].strip()
                                interfaces[current_interface] = []
                            continue
                        
                        if current_interface:
                            interfaces[current_interface].append(line.strip())
                    
                    target_interface = None
                    if self.interface_name:
                        for iface in interfaces.keys():
                            if iface == self.interface_name:
                                target_interface = iface
                                break
                    
                    if not target_interface and self.interface_mac:
                        mac_result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=10)
                        if mac_result.returncode == 0:
                            mac_output = mac_result.stdout
                            mac_pattern = r'^\d+:\s+([^:]+):.*\n\s+link/ether\s+([0-9a-fA-F:]+)'
                            mac_matches = re.findall(mac_pattern, mac_output, re.MULTILINE)
                            
                            for iface, mac in mac_matches:
                                if mac.lower() == self.interface_mac.lower():
                                    target_interface = iface
                                    break
                    
                    if not target_interface:
                        for iface, lines in interfaces.items():
                            if any('inet6' in line for line in lines):
                                target_interface = iface
                                break
                    
                    if not target_interface:
                        print("⚠️  未找到有IPv6地址的网络接口")
                        return None
                    
                    print(f"🔍 目标网络接口: {target_interface}")
                    
                    for line in interfaces[target_interface]:
                        if 'inet6' in line:
                            ipv6_match = re.search(r'inet6\s+([0-9a-fA-F:]+)', line)
                            if ipv6_match:
                                ip = ipv6_match.group(1).split('/')[0]
                                if not ip.startswith('fe80::') and ip != '::1':
                                    if self.validate_ip_address(ip, 6):
                                        print(f"✅ 从网卡获取IPv6地址: {ip}")
                                        return ip
        except Exception as e:
            print(f"⚠️  从网卡获取IPv6地址失败: {e}")
        return None

    def get_public_ip_from_api(self, ip_version: int = 4) -> Optional[str]:
        """从公网API获取IP地址[1](@ref)"""
        apis = self.ipv4_apis if ip_version == 4 else self.ipv6_apis
        ip_type = "IPv4" if ip_version == 4 else "IPv6"
        
        for api in apis:
            try:
                response = requests.get(api, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and self.validate_ip_address(ip, ip_version):
                        print(f"✅ 从API获取{ip_type}地址: {ip} (来自: {api})")
                        return ip
            except Exception as e:
                print(f"⚠️  {api} 获取失败: {e}")
                continue
        
        print(f"❌ 所有{ip_type} API均获取失败")
        return None

    def get_ip_address(self, ip_version: int = 4) -> Optional[str]:
        """根据配置获取IP地址"""
        if self.ip_source == 'network_interface':
            if ip_version == 4:
                return self.get_interface_ipv4_address()
            else:
                return self.get_interface_ipv6_address()
        else:
            return self.get_public_ip_from_api(ip_version)

    def update_dns_record(self, ipv4: Optional[str] = None, ipv6: Optional[str] = None) -> Tuple[bool, str]:
        """更新DNS记录[1](@ref)"""
        if not self.domain or not self.token:
            error_msg = "❌ 缺少域名或token配置"
            return False, error_msg
        
        results = []
        
        # 更新IPv4记录
        if ipv4 and self.enable_ipv4 and self.validate_ip_address(ipv4, 4):
            ipv4_url = f"http://dynv6.com/api/update?hostname={self.domain}&token={self.token}&ipv4={ipv4}"
            try:
                response = requests.get(ipv4_url, timeout=10)
                if response.status_code == 200:
                    results.append(f"IPv4更新成功: {response.text.strip()}")
                    print(f"✅ IPv4更新成功: {ipv4}")
                else:
                    results.append(f"IPv4更新失败: HTTP {response.status_code}")
                    print(f"❌ IPv4更新失败: {response.text}")
            except Exception as e:
                results.append(f"IPv4更新异常: {e}")
                print(f"❌ IPv4更新异常: {e}")
        
        # 更新IPv6记录
        if ipv6 and self.enable_ipv6 and self.validate_ip_address(ipv6, 6):
            ipv6_url = f"http://dynv6.com/api/update?hostname={self.domain}&token={self.token}&ipv6={ipv6}"
            try:
                response = requests.get(ipv6_url, timeout=10)
                if response.status_code == 200:
                    results.append(f"IPv6更新成功: {response.text.strip()}")
                    print(f"✅ IPv6更新成功: {ipv6}")
                else:
                    results.append(f"IPv6更新失败: HTTP {response.status_code}")
                    print(f"❌ IPv6更新失败: {response.text}")
            except Exception as e:
                results.append(f"IPv6更新异常: {e}")
                print(f"❌ IPv6更新异常: {e}")
        
        if not results:
            return False, "❌ 没有有效的IP地址需要更新"
        
        return True, " | ".join(results)

    def run_once(self) -> bool:
        """执行单次DDNS更新"""
        print("=" * 50)
        print("🚀 dynv6 DDNS 脚本开始执行")
        print(f"📋 配置信息 - 域名: {self.domain}")
        print(f"📡 IP获取方式: {self.ip_source}")
        print(f"🔧 功能设置 - IPv4: {self.enable_ipv4}, IPv6: {self.enable_ipv6}")
        print("=" * 50)
        
        # 验证基础配置
        if not self.domain or not self.token:
            error_msg = "❌ 错误: 请设置DYNV6_DOMAIN和DYNV6_TOKEN环境变量"
            send('dynv6 DDNS 配置错误', error_msg)
            return False
        
        # 加载上次的IP记录[3](@ref)
        last_ips = self.load_last_ips()
        print(f"📊 上次IP记录 - IPv4: {last_ips['ipv4'] or '无'}, IPv6: {last_ips['ipv6'] or '无'}")
        
        # 获取当前IP地址
        ipv4_addr = self.get_ip_address(4) if self.enable_ipv4 else None
        ipv6_addr = self.get_ip_address(6) if self.enable_ipv6 else None
        
        # 检查IP是否发生变化[3](@ref)
        ip_changed = False
        if self.enable_ipv4 and ipv4_addr and ipv4_addr != last_ips['ipv4']:
            ip_changed = True
            print("🔀 IPv4地址发生变化")
        elif self.enable_ipv4 and ipv4_addr:
            print("⚡ IPv4地址未变化")
        
        if self.enable_ipv6 and ipv6_addr and ipv6_addr != last_ips['ipv6']:
            ip_changed = True
            print("🔀 IPv6地址发生变化")
        elif self.enable_ipv6 and ipv6_addr:
            print("⚡ IPv6地址未变化")
        
        # 如果IP没有变化，直接退出不发送通知[3](@ref)
        if not ip_changed:
            print("✅ IP地址无变化，跳过更新操作")
            return True
        
        print("🔄 检测到IP地址变化，开始更新DNS记录...")
        
        if not ipv4_addr and not ipv6_addr:
            error_msg = "❌ 错误: 无法获取任何IP地址"
            send('dynv6 DDNS 执行失败', error_msg)
            return False
        
        # 更新DNS记录
        success, result_msg = self.update_dns_record(ipv4_addr, ipv6_addr)
        
        # 发送通知（只有在IP变化且尝试更新后才发送）
        if success:
            # 保存当前IP地址
            self.save_current_ips(ipv4_addr, ipv6_addr)
            
            update_details = []
            if ipv4_addr:
                update_details.append(f"IPv4: {ipv4_addr}")
            if ipv6_addr:
                update_details.append(f"IPv6: {ipv6_addr}")
            
            ip_source_info = f"IP来源: {self.ip_source}"
            notify_content = f"域名: {self.domain}\n{ip_source_info}\n更新时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n" + "\n".join(update_details)
            send('✅ dynv6 DDNS 更新成功', notify_content)
            print("✅ DNS更新完成，通知已发送")
        else:
            send('❌ dynv6 DDNS 更新失败', f"域名: {self.domain}\n错误信息: {result_msg}")
            print(f"❌ DNS更新失败: {result_msg}")
        
        return success

def main():
    """主函数"""
    ddns = DynV6DDNS()
    
    # 检查是否启用连续运行模式
    if os.getenv('DYNV6_CONTINUOUS', 'false').lower() == 'true':
        print("🔄 启用连续运行模式")
        while True:
            ddns.run_once()
            interval = int(os.getenv('DYNV6_CHECK_INTERVAL', '60'))
            print(f"⏰ 等待 {interval} 秒后再次检查...")
            time.sleep(interval)
    else:
        # 单次运行模式
        success = ddns.run_once()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
