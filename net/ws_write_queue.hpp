#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <utility>

namespace pm::net::detail {

// Retained application messages survive reconnects. Connection-scoped
// subscription/authentication/keepalive frames belong to exactly one socket
// generation and must never leak into the next session.
class WsWriteQueue {
public:
    explicit WsWriteQueue(std::size_t capacity = 1024,
        std::size_t connection_reserve = 16)
        : capacity_(capacity)
        , connection_reserve_(std::min(connection_reserve, capacity))
    {
    }

    bool push_retained(std::string text)
    {
        if (entries_.size() >= capacity_ - connection_reserve_)
            return false;
        entries_.push_back(entry(std::move(text), false, 0));
        return true;
    }

    bool push_connection(std::string text, std::uint64_t generation,
        bool priority)
    {
        discard_stale_connection_writes(generation);
        if (entries_.size() >= capacity_)
            return false;
        auto value = entry(std::move(text), true, generation);
        if (priority)
            entries_.push_front(std::move(value));
        else
            entries_.push_back(std::move(value));
        return true;
    }

    void discard_connection_writes(std::uint64_t generation)
    {
        std::erase_if(entries_, [generation](const Entry& value) {
            return value.connection_scoped && value.generation == generation;
        });
    }

    void discard_stale_connection_writes(std::uint64_t generation)
    {
        std::erase_if(entries_, [generation](const Entry& value) {
            return value.connection_scoped && value.generation != generation;
        });
    }

    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

    [[nodiscard]] std::shared_ptr<const std::string> front_payload() const
    {
        return entries_.front().payload;
    }

    void pop_front() { entries_.pop_front(); }
    void complete(const std::shared_ptr<const std::string>& payload)
    {
        const auto found = std::ranges::find(
            entries_, payload, &Entry::payload);
        if (found != entries_.end())
            entries_.erase(found);
    }
    void clear() noexcept { entries_.clear(); }

private:
    struct Entry {
        std::shared_ptr<const std::string> payload;
        bool connection_scoped = false;
        std::uint64_t generation = 0;
    };

    static Entry entry(std::string text, bool scoped, std::uint64_t generation)
    {
        return {
            .payload = std::make_shared<const std::string>(std::move(text)),
            .connection_scoped = scoped,
            .generation = generation,
        };
    }

    std::size_t capacity_;
    std::size_t connection_reserve_;
    std::deque<Entry> entries_;
};

} // namespace pm::net::detail
