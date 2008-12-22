#ifndef __ROUTING_TREE_WALKER_
#define __ROUTING_TREE_WALKER_
template <class BinaryType>
void routingTreeWalker(BinaryType bytes ,RoutingTreeNode * node,u_int8_t length,u_int16_t mux)
{
	for (int i=0; i<(length/8); i++)
	{
		if (!node->nodes_[bytes[i]])
			node->nodes_[bytes[i]] = new RoutingTreeNode;
		node=node->nodes_[bytes[i]];
	}
	if (length%8)
	{
		unsigned char idx=0xff;
		idx <<=8-(length%8);
		idx &= bytes[length/8];
		unsigned char maxidx=0xff;
		maxidx>>=(length%8);
		maxidx|=idx;
		for (unsigned char i=idx; i<=maxidx; i++)
		{
			if (!node->nodes_[i])
				node->nodes_[i] = new RoutingTreeNode;
			node->nodes_[i]->valid_=true;
			node->nodes_[i]->mux_=mux;
		}
	} else {
		node->valid_=true;
		node->mux_=mux;
	}
}

template <class BinaryType>
u_int16_t routingTreeFinder(BinaryType bytes ,RoutingTreeNode & root )
{
	bool valid=0;
	u_int16_t mux;
	RoutingTreeNode * node = &root;
	if (root.valid_)
	{
		mux=root.mux_;
		valid=1;
	}
	for (size_t level=0;level<bytes.size();level++)
	{
		if (node->nodes_[bytes[level]])
		{
			node=node->nodes_[bytes[level]];
			if(node->valid_)
			{
				mux=node->mux_;
				valid=1;
			}
		} else {
		 break;
		}
	}
	if(!valid)
		throw std::runtime_error("no route");
	return mux;
}
#endif

