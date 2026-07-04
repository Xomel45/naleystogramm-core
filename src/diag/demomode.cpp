#include "naleystogramm-core/diag/demomode.h"
#include "naleystogramm-core/storage/sessionmanager.h"
#include <algorithm>

DemoMode& DemoMode::instance() {
    static DemoMode inst;
    return inst;
}

void DemoMode::setEnabled(bool on) {
    if (m_enabled == on) return;
    m_enabled = on;
    SessionManager::instance().setDemoMode(on);
    for (auto& [token, fn] : m_listeners) fn(on);
}

std::string DemoMode::displayName(const std::string& real) const { return m_enabled ? kDemoName : real; }
std::string DemoMode::uuid(const std::string& real)        const { return m_enabled ? kDemoUuid : real; }
std::string DemoMode::ip(const std::string& real)          const { return m_enabled ? kDemoIp   : real; }
uint16_t    DemoMode::port(uint16_t real)                  const { return m_enabled ? kDemoPort : real; }

DemoMode::Token DemoMode::subscribe(std::function<void(bool)> fn) {
    Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(fn));
    return t;
}

void DemoMode::unsubscribe(Token t) {
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                       [t](const auto& p){ return p.first == t; }),
        m_listeners.end());
}
